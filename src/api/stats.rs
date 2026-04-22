// src/api/stats.rs
use crate::api::rustray::app::stats::command::{
    GetStatsOnlineIpListResponse, GetStatsRequest, GetStatsResponse, QueryStatsRequest,
    QueryStatsResponse, Stat, SysStatsRequest, SysStatsResponse,
    stats_service_server::StatsService,
};
use crate::app::stats::StatsManager;
use regex::Regex;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::SystemTime;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

/// Implementation of the StatsService for querying traffic statistics.
pub struct StatsServiceImpl {
    stats_manager: Arc<StatsManager>,
    start_time: SystemTime,
}

impl StatsServiceImpl {
    pub fn new(stats_manager: Arc<StatsManager>) -> Self {
        Self {
            stats_manager,
            start_time: SystemTime::now(),
        }
    }
}

#[tonic::async_trait]
impl StatsService for StatsServiceImpl {
    async fn get_stats(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        let req = request.into_inner();
        let name = req.name;
        let reset = req.reset;

        info!("Getting stats for: {}", name);

        // Get the counter value
        let value = if reset {
            // Get and reset
            if let Some(counter) = self.stats_manager.counters.get(&name) {
                counter.swap(0, Ordering::Relaxed)
            } else {
                0
            }
        } else {
            // Just get
            self.stats_manager.get_stats(&name)
        };

        let stat = Stat {
            name: name.clone(),
            value: value as i64,
        };

        Ok(Response::new(GetStatsResponse { stat: Some(stat) }))
    }

    async fn get_stats_online(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        // For now, treat this the same as get_stats
        // In a full implementation, this would track online users
        self.get_stats(request).await
    }

    async fn query_stats(
        &self,
        request: Request<QueryStatsRequest>,
    ) -> Result<Response<QueryStatsResponse>, Status> {
        let req = request.into_inner();
        let pattern = req.pattern;
        let reset = req.reset;

        info!("Querying stats with pattern: {}", pattern);

        // Compile regex pattern
        let regex = match Regex::new(&pattern) {
            Ok(r) => r,
            Err(e) => {
                warn!("Invalid regex pattern '{}': {}", pattern, e);
                return Err(Status::invalid_argument(format!(
                    "Invalid regex pattern: {}",
                    e
                )));
            }
        };

        // Collect matching stats
        let mut stats = Vec::new();

        for entry in self.stats_manager.counters.iter() {
            let name = entry.key();
            if regex.is_match(name) {
                let value = if reset {
                    entry.value().swap(0, Ordering::Relaxed)
                } else {
                    entry.value().load(Ordering::Relaxed)
                };

                stats.push(Stat {
                    name: name.clone(),
                    value: value as i64,
                });
            }
        }

        info!("Found {} matching stats", stats.len());

        Ok(Response::new(QueryStatsResponse { stat: stats }))
    }

    async fn get_sys_stats(
        &self,
        _request: Request<SysStatsRequest>,
    ) -> Result<Response<SysStatsResponse>, Status> {
        info!("Getting system stats");

        // Calculate uptime
        let uptime = self.start_time.elapsed().unwrap_or_default().as_secs() as u32;

        // Memory stats (placeholder - could integrate with allocator stats)
        let (alloc, total_alloc, sys_mem) = (0u64, 0u64, 0u64);

        // For Rust, we don't have direct goroutine/GC equivalents
        // These are Go-specific metrics, so we'll return placeholder values
        let response = SysStatsResponse {
            num_goroutine: 0,  // Not applicable in Rust
            num_gc: 0,         // Not applicable in Rust
            alloc,             // Current allocated memory
            total_alloc,       // Total allocated memory
            sys: sys_mem,      // System memory
            mallocs: 0,        // Memory allocations count
            frees: 0,          // Memory frees count
            live_objects: 0,   // Live objects count
            pause_total_ns: 0, // GC pause time (not applicable)
            uptime,            // Uptime in seconds
        };

        Ok(Response::new(response))
    }

    async fn get_stats_online_ip_list(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsOnlineIpListResponse>, Status> {
        let req = request.into_inner();
        let name = req.name;

        info!("Getting online IP list for: {}", name);

        // Get online IPs from the StatsManager
        let ips = self.stats_manager.get_online_ips(&name);

        let response = GetStatsOnlineIpListResponse {
            name: name.clone(),
            ips,
        };

        Ok(Response::new(response))
    }
}
