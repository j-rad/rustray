include $(TOPDIR)/rules.mk

PKG_NAME:=rustray
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/EdgeRay/rustray
PKG_SOURCE_VERSION:=HEAD
PKG_MIRROR_HASH:=skip

PKG_BUILD_DEPENDS:=rust/host
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=EdgeRay Team <contact@edgeray.io>

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Package/rustray
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=RustRay High-Performance Proxy Server
  URL:=https://edgeray.io
  DEPENDS:=+libc +libpthread +ca-certificates
endef

define Package/rustray/description
  RustRay is a production-grade proxy server with userspace networking stack.
  
  Features:
   - Userspace TCP/IP implementation with smoltcp
   - Multi-protocol support (VLESS, Trojan, Flow-J)
   - Mesh networking with P2P capabilities
   - Embedded web dashboard
   - Memory footprint < 50MB
   - Binary size < 4.5MB (stripped)
endef

define Package/rustray/conffiles
/etc/rustray/config.json
/etc/config/rustray
endef

# Extreme optimization for embedded targets
RUSTFLAGS:= \
	-C target-cpu=native \
	-C opt-level=z \
	-C lto=fat \
	-C codegen-units=1 \
	-C panic=abort \
	-C strip=symbols

define Build/Compile
	cd $(PKG_BUILD_DIR) && \
	CARGO_HOME=$(CARGO_HOME) \
	RUSTFLAGS="$(RUSTFLAGS)" \
	cargo build --release \
		--target=$(RUSTC_TARGET_ARCH) \
		--features minimal-server \
		--no-default-features \
		-Z build-std=std,panic_abort \
		-Z build-std-features=panic_immediate_abort
endef

define Package/rustray/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/target/$(RUSTC_TARGET_ARCH)/release/rustray $(1)/usr/bin/
	
	$(INSTALL_DIR) $(1)/etc/rustray
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/config.example.json $(1)/etc/rustray/config.json
	
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/rustray.init $(1)/etc/init.d/rustray
	
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/rustray.uci $(1)/etc/config/rustray
endef

define Package/rustray/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	/etc/init.d/rustray enable
	/etc/init.d/rustray start
}
exit 0
endef

define Package/rustray/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	/etc/init.d/rustray stop
	/etc/init.d/rustray disable
}
exit 0
endef

$(eval $(call BuildPackage,rustray))
