"""Model-specific Akuvox display-branding capabilities.

Akuvox does not expose one consistent "theme" API across its fleet.  This
module records the surfaces and file constraints verified for each model so a
deployment can fail closed instead of uploading an image intended for another
screen size or firmware family.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class BrandSurface(StrEnum):
    """Display surfaces that can accept branded artwork."""

    SCREEN_SAVER = "screen_saver"
    BOOT_ANIMATION = "boot_animation"
    TENANT_BACKGROUND = "tenant_background"
    DIAL_TIPS_BACKGROUND = "dial_tips_background"
    HOME_BUTTON_ICON = "home_button_icon"
    HOME_BUTTON_ICON_FEATURE = "home_button_icon_feature"
    HOME_PAGE_FOREGROUND = "home_page_foreground"
    HOME_PAGE_LOGO = "home_page_logo"


class BrandAssetSpec(BaseModel):
    """File constraints for one model-specific branding surface."""

    surface: BrandSurface
    destination: str
    width: int
    height: int
    formats: tuple[str, ...]
    max_bytes: int
    indexed: bool = False
    exact_dimensions: bool = True
    notes: str = ""


class ModelBrandingProfile(BaseModel):
    """Branding capabilities verified for one Akuvox model family."""

    model: str
    themes: dict[int, str]
    assets: tuple[BrandAssetSpec, ...]
    supports_button_labels: bool
    supports_page_prompts: bool
    supports_custom_home_icons: bool
    supports_home_button_colors: bool
    notes: tuple[str, ...] = ()

    def asset(self, surface: BrandSurface) -> BrandAssetSpec:
        """Return the asset specification for *surface* or fail explicitly."""
        for spec in self.assets:
            if spec.surface == surface:
                return spec
        raise KeyError(f"{self.model} does not support {surface.value}")


S535_PROFILE = ModelBrandingProfile(
    model="S535",
    themes={1: "Villa", 2: "Building", 3: "Speed Dial", 4: "QR Code"},
    assets=(
        BrandAssetSpec(
            surface=BrandSurface.SCREEN_SAVER,
            destination="Screensaver",
            width=800,
            height=1280,
            formats=(".jpg", ".jpeg"),
            max_bytes=2_000_000,
            indexed=True,
            notes="Up to five rotating images; official recommended resolution.",
        ),
        BrandAssetSpec(
            surface=BrandSurface.BOOT_ANIMATION,
            destination="BootAnimation",
            width=800,
            height=1280,
            formats=(".png", ".zip"),
            max_bytes=1024 * 1024,
            exact_dimensions=False,
            notes=(
                "Static PNG at or below 800x1280 and 1 MB. Animation ZIPs have "
                "a separate 20 MB limit. Visible after a reboot."
            ),
        ),
        BrandAssetSpec(
            surface=BrandSurface.TENANT_BACKGROUND,
            destination="BackgroundOfContact",
            width=800,
            height=1280,
            formats=(".png",),
            max_bytes=1024 * 1024,
            notes="Background of the tenant/directory list.",
        ),
        BrandAssetSpec(
            surface=BrandSurface.DIAL_TIPS_BACKGROUND,
            destination="BackgroundOfTimeView",
            width=800,
            height=400,
            formats=(".png",),
            max_bytes=1024 * 1024,
            notes="Background of the dial-instruction area.",
        ),
    ),
    supports_button_labels=True,
    supports_page_prompts=True,
    supports_custom_home_icons=False,
    supports_home_button_colors=False,
    notes=(
        "Verified against S535 firmware 535.30.10.236.",
        "The Building-theme home buttons retain the firmware's native icons and colors.",
        "Button labels are limited to eight characters on this firmware.",
        (
            "This beta firmware advertises tenant and dial backgrounds in its web UI, "
            "but its backend may reject those upload destinations."
        ),
        (
            "The monitoring-center speed-dial icon is a protected functional color "
            "and must remain purple; its action and number must not change."
        ),
    ),
)

A05_PROFILE = ModelBrandingProfile(
    model="A05",
    themes={0: "Default", 1: "QR Code", 2: "Speed Dial", 3: "Custom UI"},
    assets=(
        BrandAssetSpec(
            surface=BrandSurface.SCREEN_SAVER,
            destination="Screensaver",
            width=720,
            height=1280,
            formats=(".jpg", ".jpeg", ".png"),
            max_bytes=2 * 1024 * 1024,
            indexed=True,
            notes=(
                "Akuvox-recommended A05 portrait resolution. The physical LCD is "
                "1280x720 but portrait artwork is uploaded as 720x1280."
            ),
        ),
        BrandAssetSpec(
            surface=BrandSurface.TENANT_BACKGROUND,
            destination="CustomUIBackground",
            width=720,
            height=1280,
            formats=(".jpg", ".jpeg", ".png"),
            max_bytes=2 * 1024 * 1024,
            notes=(
                "Custom UI homepage background. Use contain/crop-safe artwork "
                "because the active button template changes usable space."
            ),
        ),
        BrandAssetSpec(
            surface=BrandSurface.HOME_BUTTON_ICON,
            destination="CustomUIButtonIcon",
            width=256,
            height=256,
            formats=(".jpg", ".jpeg", ".png"),
            max_bytes=1024 * 1024,
            notes=(
                "Square transparent master for firmware scaling. Akuvox documents "
                "custom JPG/PNG icons but no fixed pixel size for A05."
            ),
        ),
    ),
    supports_button_labels=True,
    supports_page_prompts=True,
    supports_custom_home_icons=True,
    supports_home_button_colors=True,
    notes=(
        "Package based on Akuvox A05 Custom UI documentation and 720x1280 upload guidance.",
        (
            "A live A05 firmware audit is still required before automated deployment; "
            "the reference unit was unreachable during package preparation."
        ),
        (
            "Do not replace or recolor the Speed Dial icon. Preserve the original "
            "purple monitoring-center control, action, and number."
        ),
    ),
)

R29C_PROFILE = ModelBrandingProfile(
    model="R29C",
    themes={1: "Villa", 2: "Building", 3: "Office", 4: "Alphanumeric"},
    assets=(
        BrandAssetSpec(
            surface=BrandSurface.SCREEN_SAVER,
            destination="SendImage",
            width=800,
            height=1280,
            formats=(".jpg", ".jpeg"),
            max_bytes=2 * 1024 * 1024,
            indexed=True,
            notes="Up to five JPG images; verified in the legacy R29C web UI.",
        ),
        BrandAssetSpec(
            surface=BrandSurface.HOME_BUTTON_ICON,
            destination="ButtonIcon",
            width=256,
            height=256,
            formats=(".png",),
            max_bytes=1024 * 1024,
            notes=(
                "Transparent square PNG chosen for the scalable home-button slot. "
                "SpeedDial and SpeedDial2 are protected and deliberately omitted."
            ),
        ),
    ),
    supports_button_labels=True,
    supports_page_prompts=True,
    supports_custom_home_icons=True,
    supports_home_button_colors=True,
    notes=(
        "Verified against R29C firmware 29.30.10.247.",
        "Legacy FCGI upload controls differ from the newer S535 HTTP API.",
        (
            "Do not upload SpeedDial or SpeedDial2 artwork and do not change the "
            "foreground color: the monitoring-center speed-dial must remain purple."
        ),
        "Button types, call numbers, relay behavior, and tenant data are out of scope.",
    ),
)

X916_PROFILE = ModelBrandingProfile(
    model="X916",
    themes={2: "Intercom (legacy Building layout)"},
    assets=(
        BrandAssetSpec(
            surface=BrandSurface.SCREEN_SAVER,
            destination="SendImage",
            width=2560,
            height=1600,
            formats=(".jpg", ".jpeg"),
            max_bytes=2 * 1024 * 1024,
            indexed=True,
            notes=(
                "Up to five rotating images. Akuvox recommends 2560x1600; "
                "verify the older firmware upload result."
            ),
        ),
        BrandAssetSpec(
            surface=BrandSurface.BOOT_ANIMATION,
            destination="ImportBootAnimation",
            width=1920,
            height=1080,
            formats=(".png", ".zip"),
            max_bytes=2 * 1024 * 1024,
            notes=(
                "Static PNG limit. Firmware 916.30.10.114 advertises a 40 MB "
                "ZIP limit while current Akuvox documentation says 20 MB."
            ),
        ),
        BrandAssetSpec(
            surface=BrandSurface.HOME_PAGE_FOREGROUND,
            destination="ImportForeground",
            width=1076,
            height=720,
            formats=(".png",),
            max_bytes=1024 * 1024,
            notes="Homepage foreground/left-side branded image.",
        ),
        BrandAssetSpec(
            surface=BrandSurface.HOME_PAGE_LOGO,
            destination="ImportLogo",
            width=406,
            height=116,
            formats=(".png",),
            max_bytes=1024 * 1024,
            notes=("On-screen logo; the physical Akuvox bezel mark is not editable."),
        ),
        BrandAssetSpec(
            surface=BrandSurface.HOME_BUTTON_ICON,
            destination="ButtonIcon",
            width=218,
            height=176,
            formats=(".png",),
            max_bytes=1024 * 1024,
            notes=(
                "Native compact function-tile size read from firmware "
                "916.30.10.114. Re-export when the key count/layout changes."
            ),
        ),
        BrandAssetSpec(
            surface=BrandSurface.HOME_BUTTON_ICON_FEATURE,
            destination="ButtonIcon",
            width=371,
            height=312,
            formats=(".png",),
            max_bytes=1024 * 1024,
            notes=(
                "Native Face/feature-tile canvas read from the device and "
                "shown as an example recommendation in current Akuvox docs."
            ),
        ),
    ),
    supports_button_labels=True,
    supports_page_prompts=True,
    supports_custom_home_icons=True,
    supports_home_button_colors=True,
    notes=(
        "Read-only audited against X916 firmware 916.30.10.114.",
        ("Current Akuvox firmware supports 0-16 keys and recommends icon size dynamically."),
        "Firmware 916.30.10.114 exposes a fixed six-key Intercom layout.",
        (
            "Do not upload SpeedDial artwork or change its number/action: the "
            "monitoring-center button must remain the original purple."
        ),
    ),
)

S539_PROFILE = ModelBrandingProfile(
    model="S539",
    themes={
        1: "Villa",
        2: "Building",
        3: "Office",
        4: "Multi-factor Authentication",
        5: "Alphanumeric",
    },
    assets=(
        BrandAssetSpec(
            surface=BrandSurface.SCREEN_SAVER,
            destination="Screensaver",
            width=1080,
            height=1920,
            formats=(".jpg", ".jpeg"),
            max_bytes=2 * 1024 * 1024,
            indexed=True,
            exact_dimensions=False,
            notes=(
                "Up to five JPG images. Akuvox currently recommends 1080x1920 "
                "while describing the limit as 2M pixels; keep compressed files "
                "below 2 MB and verify on the firmware canary."
            ),
        ),
        BrandAssetSpec(
            surface=BrandSurface.BOOT_ANIMATION,
            destination="BootAnimation",
            width=800,
            height=1280,
            formats=(".png", ".zip"),
            max_bytes=1024 * 1024,
            notes=(
                "Verified on firmware 539.30.10.130 and .428: static PNG up to "
                "1 MB; animation ZIP up to 20 MB."
            ),
        ),
        BrandAssetSpec(
            surface=BrandSurface.TENANT_BACKGROUND,
            destination="BackgroundOfDirectoryList",
            width=800,
            height=1280,
            formats=(".png", ".jpg", ".jpeg"),
            max_bytes=1024 * 1024,
            notes=(
                "Available directly on .130. On .428 select Appearance > "
                "Customization to expose this upload."
            ),
        ),
    ),
    supports_button_labels=True,
    supports_page_prompts=True,
    supports_custom_home_icons=False,
    supports_home_button_colors=False,
    notes=(
        "Read-only audited against S539 firmware 539.30.10.130 and .428.",
        (
            "Firmware .428 provides built-in Light, Dark, and holiday resident "
            "themes; .130 has no Appearance selector."
        ),
        (
            "Current Akuvox documentation describes 120x120 custom Building-theme "
            "icons, but the audited .130/.428 web UIs do not expose that upload. "
            "Treat the staged 120x120 icons as firmware-upgrade-ready only."
        ),
        (
            "Do not upload Speed Dial artwork or change its number/action: the "
            "monitoring-center control remains protected and purple."
        ),
    ),
)


MODEL_BRANDING_PROFILES = {
    A05_PROFILE.model: A05_PROFILE,
    S535_PROFILE.model: S535_PROFILE,
    S539_PROFILE.model: S539_PROFILE,
    R29C_PROFILE.model: R29C_PROFILE,
    X916_PROFILE.model: X916_PROFILE,
}


def branding_profile_for(model: str) -> ModelBrandingProfile:
    """Return the verified branding profile for *model*.

    Model matching is intentionally exact.  Similar-looking Akuvox panels can
    have different resolutions, upload endpoints, and menu semantics.
    """
    normalized = model.strip().upper()
    try:
        return MODEL_BRANDING_PROFILES[normalized]
    except KeyError as exc:
        raise KeyError(f"No verified branding profile for Akuvox {normalized}") from exc
