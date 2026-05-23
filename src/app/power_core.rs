use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use tracing::info;

/// Global battery level (0-100)
static BATTERY_LEVEL: AtomicU8 = AtomicU8::new(100);
/// Global screen state
static SCREEN_ON: AtomicBool = AtomicBool::new(true);
/// Global power saving override
static POWER_SAVING_MODE: AtomicBool = AtomicBool::new(false);

/// Updates the global battery level.
pub fn update_battery(level: u8) {
    BATTERY_LEVEL.store(level, Ordering::SeqCst);
    check_power_state();
}

/// Updates the global screen state.
pub fn update_screen_state(on: bool) {
    SCREEN_ON.store(on, Ordering::SeqCst);
    check_power_state();
}

/// Checks the current state and updates the power saving flag.
fn check_power_state() {
    let battery = BATTERY_LEVEL.load(Ordering::SeqCst);
    let screen_on = SCREEN_ON.load(Ordering::SeqCst);

    let should_save = battery < 15 || !screen_on;
    let old_state = POWER_SAVING_MODE.swap(should_save, Ordering::SeqCst);

    if should_save != old_state {
        if should_save {
            info!(
                "PowerCore: Entering Low-Power mode (Battery: {}%, Screen: {}). Disabling transport jitter/padding.",
                battery,
                if screen_on { "ON" } else { "OFF" }
            );
        } else {
            info!("PowerCore: Resuming high-fidelity transport shaping.");
        }
    }
}

/// Returns true if high-cost transport features (jitter, padding) should be disabled.
pub fn is_shaping_disabled() -> bool {
    POWER_SAVING_MODE.load(Ordering::Relaxed)
}

/// Forced override for power saving (e.g. from UI settings)
pub fn set_power_saving_override(enabled: bool) {
    POWER_SAVING_MODE.store(enabled, Ordering::SeqCst);
}
