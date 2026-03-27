// src/api/handler.rs
use crate::api::rustray::app::proxyman::command::{
    AddInboundRequest, AddInboundResponse, AddOutboundRequest, AddOutboundResponse,
    AlterInboundRequest, AlterInboundResponse, AlterOutboundRequest, AlterOutboundResponse,
    GetInboundUserRequest, GetInboundUserResponse, GetInboundUsersCountResponse,
    ListInboundsRequest, ListInboundsResponse, ListOutboundsRequest, ListOutboundsResponse,
    RemoveInboundRequest, RemoveInboundResponse, RemoveOutboundRequest, RemoveOutboundResponse,
    handler_service_server::HandlerService,
};
use crate::app::stats::{ConfigEvent, StatsManager};
use crate::config::{Inbound, InboundSettings, Outbound, TrojanUser, VlessUser, VmessUser};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

/// Implementation of the HandlerService for managing inbounds and outbounds dynamically.
pub struct HandlerServiceImpl {
    stats_manager: Arc<StatsManager>,
}

impl HandlerServiceImpl {
    pub fn new(stats_manager: Arc<StatsManager>) -> Self {
        Self { stats_manager }
    }

    /// Convert protobuf InboundHandlerConfig to internal Inbound struct
    fn proto_to_inbound(
        proto_inbound: crate::api::rustray::core::InboundHandlerConfig,
    ) -> Result<Inbound, Status> {
        // Extract tag from proto
        let tag = proto_inbound.tag;

        // Parse proxy_settings to determine protocol and settings
        let proxy_settings = proto_inbound
            .proxy_settings
            .ok_or_else(|| Status::invalid_argument("Missing proxy_settings"))?;

        // The TypedMessage contains a type string and serialized value
        // For simplicity, we'll try to deserialize as JSON from the value field
        let protocol = extract_protocol_from_type(&proxy_settings.r#type);

        // Parse receiver_settings for port and listen address
        let receiver_settings = proto_inbound.receiver_settings;
        let (port, listen) = if let Some(recv) = receiver_settings {
            // Try to parse as JSON to extract port and listen
            match serde_json::from_slice::<serde_json::Value>(&recv.value) {
                Ok(json) => {
                    let port = json.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    let listen = json
                        .get("listen")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    (port, listen)
                }
                Err(_) => (0, None),
            }
        } else {
            (0, None)
        };

        // Parse settings from proxy_settings.value
        let settings: Option<InboundSettings> = match serde_json::from_slice(&proxy_settings.value)
        {
            Ok(s) => Some(s),
            Err(e) => {
                warn!("Failed to parse inbound settings: {}", e);
                None
            }
        };

        Ok(Inbound {
            tag,
            port,
            listen,
            protocol,
            settings,
            stream_settings: None,
            sniffing: None,
            allocation: None,
        })
    }

    /// Convert protobuf OutboundHandlerConfig to internal Outbound struct
    fn proto_to_outbound(
        proto_outbound: crate::api::rustray::core::OutboundHandlerConfig,
    ) -> Result<Outbound, Status> {
        let tag = proto_outbound.tag;

        let proxy_settings = proto_outbound
            .proxy_settings
            .ok_or_else(|| Status::invalid_argument("Missing proxy_settings"))?;

        let protocol = extract_protocol_from_type(&proxy_settings.r#type);

        let settings = match serde_json::from_slice(&proxy_settings.value) {
            Ok(s) => Some(s),
            Err(e) => {
                warn!("Failed to parse outbound settings: {}", e);
                None
            }
        };

        Ok(Outbound {
            tag,
            protocol,
            settings,
            stream_settings: None,
            mux: None,
            proxy_settings: None,
        })
    }
}

#[tonic::async_trait]
impl HandlerService for HandlerServiceImpl {
    async fn add_inbound(
        &self,
        request: Request<AddInboundRequest>,
    ) -> Result<Response<AddInboundResponse>, Status> {
        let req = request.into_inner();
        let proto_inbound = req
            .inbound
            .ok_or_else(|| Status::invalid_argument("Missing inbound config"))?;

        info!("Adding inbound: {}", proto_inbound.tag);

        // Convert proto to internal Inbound
        let inbound = Self::proto_to_inbound(proto_inbound)?;

        // Send event to StatsManager
        if let Err(e) = self
            .stats_manager
            .config_event_tx
            .send(ConfigEvent::InboundAdded(inbound.clone()))
        {
            error!("Failed to send InboundAdded event: {}", e);
            return Err(Status::internal("Failed to add inbound"));
        }

        // Also update the config
        let old_config = self.stats_manager.config.load();
        let mut config = (**old_config).clone();
        if let Some(ref mut inbounds) = config.inbounds {
            inbounds.push(inbound);
        } else {
            config.inbounds = Some(vec![inbound]);
        }
        self.stats_manager.config.store(Arc::new(config));

        info!("Inbound added successfully");
        Ok(Response::new(AddInboundResponse {}))
    }

    async fn remove_inbound(
        &self,
        request: Request<RemoveInboundRequest>,
    ) -> Result<Response<RemoveInboundResponse>, Status> {
        let req = request.into_inner();
        let tag = req.tag;

        info!("Removing inbound: {}", tag);

        // Send event to StatsManager
        if let Err(e) = self
            .stats_manager
            .config_event_tx
            .send(ConfigEvent::InboundRemoved(tag.clone()))
        {
            error!("Failed to send InboundRemoved event: {}", e);
            return Err(Status::internal("Failed to remove inbound"));
        }

        // Update the config
        let old_config = self.stats_manager.config.load();
        let mut config = (**old_config).clone();
        if let Some(ref mut inbounds) = config.inbounds {
            inbounds.retain(|i| i.tag != tag);
        }
        self.stats_manager.config.store(Arc::new(config));

        info!("Inbound removed successfully");
        Ok(Response::new(RemoveInboundResponse {}))
    }

    async fn alter_inbound(
        &self,
        request: Request<AlterInboundRequest>,
    ) -> Result<Response<AlterInboundResponse>, Status> {
        let req = request.into_inner();
        let tag = req.tag;
        let operation = req
            .operation
            .ok_or_else(|| Status::invalid_argument("Missing operation"))?;

        info!("Altering inbound: {}", tag);

        let old_config = self.stats_manager.config.load();
        let mut config = (**old_config).clone();
        // Find the inbound
        let inbound = if let Some(inbounds) = &mut config.inbounds {
            inbounds.iter_mut().find(|i| i.tag == tag)
        } else {
            None
        };

        let inbound =
            inbound.ok_or_else(|| Status::not_found(format!("Inbound '{}' not found", tag)))?;
        let settings = inbound
            .settings
            .as_mut()
            .ok_or_else(|| Status::internal("Inbound has no settings"))?;

        info!("AlterInbound: current settings variant: {:?}", settings);

        // Handle operation
        // Simplified JSON-based approach for flexibility and compatibility with our config structs
        if operation.r#type.contains("AddUser") {
            // Expect value to be JSON of the specific User struct
            match settings {
                InboundSettings::Vless(cfg) => {
                    let user: VlessUser =
                        serde_json::from_slice(&operation.value).map_err(|e| {
                            Status::invalid_argument(format!("Failed to parse VLess user: {}", e))
                        })?;
                    cfg.clients.push(user);
                }
                InboundSettings::Vmess(cfg) => {
                    let user: VmessUser =
                        serde_json::from_slice(&operation.value).map_err(|e| {
                            Status::invalid_argument(format!("Failed to parse VMess user: {}", e))
                        })?;
                    cfg.clients.push(user);
                }
                InboundSettings::Trojan(cfg) => {
                    let user: TrojanUser =
                        serde_json::from_slice(&operation.value).map_err(|e| {
                            Status::invalid_argument(format!("Failed to parse Trojan user: {}", e))
                        })?;
                    cfg.clients.push(user);
                }
                _ => {
                    return Err(Status::invalid_argument(format!(
                        "AddUser operation not supported for protocol '{}': only VLESS, VMess, and Trojan support multiple users",
                        inbound.protocol
                    )));
                }
            }
        } else if operation.r#type.contains("RemoveUser") {
            // Expect value to be JSON with "email" field
            #[derive(serde::Deserialize)]
            struct RemovePayload {
                email: String,
            }
            let payload: RemovePayload = serde_json::from_slice(&operation.value).map_err(|e| {
                Status::invalid_argument(format!("Failed to parse RemoveUser payload: {}", e))
            })?;

            let email = payload.email;

            match settings {
                InboundSettings::Vless(cfg) => {
                    cfg.clients
                        .retain(|client| client.email.as_deref() != Some(&email));
                }
                InboundSettings::Vmess(cfg) => {
                    cfg.clients
                        .retain(|client| client.email.as_deref() != Some(&email));
                }
                InboundSettings::Trojan(cfg) => {
                    cfg.clients
                        .retain(|client| client.email.as_deref() != Some(&email));
                }
                _ => {
                    return Err(Status::invalid_argument(format!(
                        "RemoveUser operation not supported for protocol '{}': only VLESS, VMess, and Trojan support multiple users",
                        inbound.protocol
                    )));
                }
            }
        } else {
            return Err(Status::invalid_argument(format!(
                "Unknown operation type '{}': supported operations are 'AddUser' and 'RemoveUser'",
                operation.r#type
            )));
        }

        // Trigger update
        let event_inbound = inbound.clone();

        // Broadcast to InboundManager to restart the listener with new settings
        if let Err(e) = self
            .stats_manager
            .config_event_tx
            .send(ConfigEvent::InboundAdded(event_inbound))
        {
            error!("Failed to broadcast update: {}", e);
            return Err(Status::internal("Failed to apply update"));
        }

        info!("Inbound altered successfully");
        Ok(Response::new(AlterInboundResponse {}))
    }

    async fn list_inbounds(
        &self,
        request: Request<ListInboundsRequest>,
    ) -> Result<Response<ListInboundsResponse>, Status> {
        let req = request.into_inner();
        let is_only_tags = req.is_only_tags;

        let config = self.stats_manager.config.load();
        let inbounds = config
            .inbounds.clone()
            .unwrap_or_default();

        // Convert internal Inbound to proto InboundHandlerConfig
        let proto_inbounds: Vec<crate::api::rustray::core::InboundHandlerConfig> = inbounds
            .iter()
            .map(|inbound| {
                // Create TypedMessage for proxy_settings
                let proxy_settings = if !is_only_tags {
                    let settings_json = serde_json::to_vec(&inbound.settings).unwrap_or_default();
                    Some(crate::api::rustray::common::serial::TypedMessage {
                        r#type: format!("rustray.proxy.{}.Inbound", inbound.protocol),
                        value: settings_json,
                    })
                } else {
                    None
                };

                crate::api::rustray::core::InboundHandlerConfig {
                    tag: inbound.tag.clone(),
                    receiver_settings: None,
                    proxy_settings,
                }
            })
            .collect();

        Ok(Response::new(ListInboundsResponse {
            inbounds: proto_inbounds,
        }))
    }

    async fn get_inbound_users(
        &self,
        request: Request<GetInboundUserRequest>,
    ) -> Result<Response<GetInboundUserResponse>, Status> {
        let req = request.into_inner();
        let tag = req.tag;
        let email_filter = if req.email.is_empty() {
            None
        } else {
            Some(req.email)
        };

        let config = self.stats_manager.config.load();
        let inbound: Option<&Inbound> = config
            .inbounds
            .as_ref()
            .and_then(|inbounds| inbounds.iter().find(|i| i.tag == tag));

        let inbound = match inbound {
            Some(i) => i,
            None => return Err(Status::not_found(format!("Inbound '{}' not found", tag))),
        };

        let mut users = Vec::new();

        if let Some(settings) = &inbound.settings {
            match settings {
                InboundSettings::Vless(cfg) => {
                    for client in &cfg.clients {
                        if let Some(ref filter) = email_filter
                            && client.email.as_deref() != Some(filter.as_str()) {
                                continue;
                            }
                        let account_json = serde_json::to_vec(&client).unwrap_or_default();
                        users.push(crate::api::rustray::common::protocol::User {
                            level: client.level.unwrap_or(0),
                            email: client.email.clone().unwrap_or_default(),
                            account: Some(crate::api::rustray::common::serial::TypedMessage {
                                r#type: "rustray.proxy.vless.Account".to_string(),
                                value: account_json,
                            }),
                        });
                    }
                }
                InboundSettings::Vmess(cfg) => {
                    for client in &cfg.clients {
                        if let Some(ref filter) = email_filter
                            && client.email.as_deref() != Some(filter.as_str()) {
                                continue;
                            }
                        let account_json = serde_json::to_vec(&client).unwrap_or_default();
                        users.push(crate::api::rustray::common::protocol::User {
                            level: client.level.unwrap_or(0),
                            email: client.email.clone().unwrap_or_default(),
                            account: Some(crate::api::rustray::common::serial::TypedMessage {
                                r#type: "rustray.proxy.vmess.Account".to_string(),
                                value: account_json,
                            }),
                        });
                    }
                }
                InboundSettings::Trojan(cfg) => {
                    for client in &cfg.clients {
                        if let Some(ref filter) = email_filter
                            && client.email.as_deref() != Some(filter.as_str()) {
                                continue;
                            }
                        let account_json = serde_json::to_vec(&client).unwrap_or_default();
                        users.push(crate::api::rustray::common::protocol::User {
                            level: client.level.unwrap_or(0),
                            email: client.email.clone().unwrap_or_default(),
                            account: Some(crate::api::rustray::common::serial::TypedMessage {
                                r#type: "rustray.proxy.trojan.Account".to_string(),
                                value: account_json,
                            }),
                        });
                    }
                }
                _ => {
                    // Protocol doesn't support user listing
                }
            }
        }

        info!(
            "GetInboundUsers: found {} users for inbound '{}'",
            users.len(),
            tag
        );
        Ok(Response::new(GetInboundUserResponse { users }))
    }

    async fn get_inbound_users_count(
        &self,
        request: Request<GetInboundUserRequest>,
    ) -> Result<Response<GetInboundUsersCountResponse>, Status> {
        let req = request.into_inner();
        let tag = req.tag;

        let config = self.stats_manager.config.load();
        let inbound: Option<&Inbound> = config
            .inbounds
            .as_ref()
            .and_then(|inbounds| inbounds.iter().find(|i| i.tag == tag));

        let inbound = match inbound {
            Some(i) => i,
            None => return Err(Status::not_found(format!("Inbound '{}' not found", tag))),
        };

        let count = if let Some(settings) = &inbound.settings {
            match settings {
                InboundSettings::Vless(cfg) => cfg.clients.len() as i64,
                InboundSettings::Vmess(cfg) => cfg.clients.len() as i64,
                InboundSettings::Trojan(cfg) => cfg.clients.len() as i64,
                _ => 0,
            }
        } else {
            0
        };

        info!(
            "GetInboundUsersCount: {} users for inbound '{}'",
            count, tag
        );
        Ok(Response::new(GetInboundUsersCountResponse { count }))
    }

    async fn add_outbound(
        &self,
        request: Request<AddOutboundRequest>,
    ) -> Result<Response<AddOutboundResponse>, Status> {
        let req = request.into_inner();
        let proto_outbound = req
            .outbound
            .ok_or_else(|| Status::invalid_argument("Missing outbound config"))?;

        info!("Adding outbound: {}", proto_outbound.tag);

        let outbound = Self::proto_to_outbound(proto_outbound)?;

        if let Err(e) = self
            .stats_manager
            .config_event_tx
            .send(ConfigEvent::OutboundAdded(outbound.clone()))
        {
            error!("Failed to send OutboundAdded event: {}", e);
            return Err(Status::internal("Failed to add outbound"));
        }

        let old_config = self.stats_manager.config.load();
        let mut config = (**old_config).clone();
        if let Some(ref mut outbounds) = config.outbounds {
            outbounds.push(outbound);
        } else {
            config.outbounds = Some(vec![outbound]);
        }
        self.stats_manager.config.store(Arc::new(config));

        info!("Outbound added successfully");
        Ok(Response::new(AddOutboundResponse {}))
    }

    async fn remove_outbound(
        &self,
        request: Request<RemoveOutboundRequest>,
    ) -> Result<Response<RemoveOutboundResponse>, Status> {
        let req = request.into_inner();
        let tag = req.tag;

        info!("Removing outbound: {}", tag);

        if let Err(e) = self
            .stats_manager
            .config_event_tx
            .send(ConfigEvent::OutboundRemoved(tag.clone()))
        {
            error!("Failed to send OutboundRemoved event: {}", e);
            return Err(Status::internal("Failed to remove outbound"));
        }

        let old_config = self.stats_manager.config.load();
        let mut config = (**old_config).clone();
        if let Some(ref mut outbounds) = config.outbounds {
            outbounds.retain(|o| o.tag != tag);
        }
        self.stats_manager.config.store(Arc::new(config));

        info!("Outbound removed successfully");
        Ok(Response::new(RemoveOutboundResponse {}))
    }

    async fn alter_outbound(
        &self,
        request: Request<AlterOutboundRequest>,
    ) -> Result<Response<AlterOutboundResponse>, Status> {
        let req = request.into_inner();
        let tag = req.tag;
        let operation = req
            .operation
            .ok_or_else(|| Status::invalid_argument("Missing operation"))?;

        info!("Altering outbound: {}", tag);

        let old_config = self.stats_manager.config.load();
        let mut config = (**old_config).clone();
        let outbound = if let Some(outbounds) = &mut config.outbounds {
            outbounds.iter_mut().find(|o| o.tag == tag)
        } else {
            None
        };

        let outbound =
            outbound.ok_or_else(|| Status::not_found(format!("Outbound '{}' not found", tag)))?;

        // For outbounds, we mainly support replacing settings entirely
        // since most outbounds don't have multi-user configurations
        if operation.r#type.contains("UpdateSettings") {
            // Expect value to be JSON of OutboundSettings
            let new_settings: crate::config::OutboundSettings =
                serde_json::from_slice(&operation.value).map_err(|e| {
                    Status::invalid_argument(format!("Failed to parse outbound settings: {}", e))
                })?;
            outbound.settings = Some(new_settings);
        } else {
            return Err(Status::invalid_argument(format!(
                "Unknown operation type for outbound '{}': only 'UpdateSettings' is supported for outbound modifications",
                operation.r#type
            )));
        }

        // Trigger update
        let event_outbound = outbound.clone();

        if let Err(e) = self
            .stats_manager
            .config_event_tx
            .send(ConfigEvent::OutboundAdded(event_outbound))
        {
            error!("Failed to broadcast update: {}", e);
            return Err(Status::internal("Failed to apply update"));
        }

        info!("Outbound altered successfully");
        Ok(Response::new(AlterOutboundResponse {}))
    }

    async fn list_outbounds(
        &self,
        _request: Request<ListOutboundsRequest>,
    ) -> Result<Response<ListOutboundsResponse>, Status> {
        let config = self.stats_manager.config.load();
        let outbounds = config
            .outbounds.clone()
            .unwrap_or_default();

        let proto_outbounds: Vec<crate::api::rustray::core::OutboundHandlerConfig> = outbounds
            .iter()
            .map(|outbound| {
                let settings_json = serde_json::to_vec(&outbound.settings).unwrap_or_default();
                let proxy_settings = Some(crate::api::rustray::common::serial::TypedMessage {
                    r#type: format!("rustray.proxy.{}.Outbound", outbound.protocol),
                    value: settings_json,
                });

                crate::api::rustray::core::OutboundHandlerConfig {
                    tag: outbound.tag.clone(),
                    sender_settings: None,
                    proxy_settings,
                    expire: 0,
                    comment: String::new(),
                }
            })
            .collect();

        Ok(Response::new(ListOutboundsResponse {
            outbounds: proto_outbounds,
        }))
    }
}

/// Helper function to extract protocol name from TypedMessage type string
fn extract_protocol_from_type(type_str: &str) -> String {
    // Type format: "rustray.proxy.vless.Inbound" -> "vless"
    let parts: Vec<&str> = type_str.split('.').collect();
    if parts.len() >= 3 {
        parts[parts.len() - 2].to_string()
    } else {
        "unknown".to_string()
    }
}
