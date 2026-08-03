from __future__ import annotations

import pytest

from pyakuvox.branding import (
    BrandSurface,
    branding_profile_for,
)


def test_s535_profile_uses_verified_device_dimensions() -> None:
    profile = branding_profile_for("s535")

    screensaver = profile.asset(BrandSurface.SCREEN_SAVER)
    assert (screensaver.width, screensaver.height) == (800, 1280)
    assert screensaver.destination == "Screensaver"
    assert screensaver.indexed is True

    dial_background = profile.asset(BrandSurface.DIAL_TIPS_BACKGROUND)
    assert (dial_background.width, dial_background.height) == (800, 400)


def test_s535_profile_does_not_overstate_home_icon_support() -> None:
    profile = branding_profile_for("S535")

    assert profile.supports_button_labels is True
    assert profile.supports_page_prompts is True
    assert profile.supports_custom_home_icons is False
    assert profile.supports_home_button_colors is False


def test_a05_profile_custom_ui_constraints() -> None:
    profile = branding_profile_for("A05")
    screensaver = profile.asset(BrandSurface.SCREEN_SAVER)
    background = profile.asset(BrandSurface.TENANT_BACKGROUND)
    icon = profile.asset(BrandSurface.HOME_BUTTON_ICON)

    assert (screensaver.width, screensaver.height) == (720, 1280)
    assert (background.width, background.height) == (720, 1280)
    assert (icon.width, icon.height) == (256, 256)
    assert profile.supports_custom_home_icons is True
    assert profile.supports_home_button_colors is True


def test_unknown_model_fails_closed() -> None:
    with pytest.raises(KeyError, match="No verified branding profile"):
        branding_profile_for("R29")


def test_r29c_profile_supports_model_specific_artwork() -> None:
    profile = branding_profile_for("r29c")

    assert profile.supports_custom_home_icons is True
    assert profile.supports_home_button_colors is True
    assert profile.asset(BrandSurface.SCREEN_SAVER).destination == "SendImage"
    icon = profile.asset(BrandSurface.HOME_BUTTON_ICON)
    assert (icon.width, icon.height) == (256, 256)
    assert icon.max_bytes == 1024 * 1024


def test_x916_profile_records_responsive_and_branding_surfaces() -> None:
    profile = branding_profile_for("x916")
    screensaver = profile.asset(BrandSurface.SCREEN_SAVER)
    compact = profile.asset(BrandSurface.HOME_BUTTON_ICON)
    feature = profile.asset(BrandSurface.HOME_BUTTON_ICON_FEATURE)
    boot = profile.asset(BrandSurface.BOOT_ANIMATION)
    foreground = profile.asset(BrandSurface.HOME_PAGE_FOREGROUND)
    logo = profile.asset(BrandSurface.HOME_PAGE_LOGO)

    assert (screensaver.width, screensaver.height) == (2560, 1600)
    assert (compact.width, compact.height) == (218, 176)
    assert (feature.width, feature.height) == (371, 312)
    assert (boot.width, boot.height) == (1920, 1080)
    assert (foreground.width, foreground.height) == (1076, 720)
    assert (logo.width, logo.height) == (406, 116)
    assert profile.supports_custom_home_icons is True


def test_s539_profile_records_both_live_firmware_branches() -> None:
    profile = branding_profile_for("s539")
    screensaver = profile.asset(BrandSurface.SCREEN_SAVER)
    boot = profile.asset(BrandSurface.BOOT_ANIMATION)
    directory = profile.asset(BrandSurface.TENANT_BACKGROUND)

    assert (screensaver.width, screensaver.height) == (1080, 1920)
    assert screensaver.indexed is True
    assert screensaver.exact_dimensions is False
    assert (boot.width, boot.height) == (800, 1280)
    assert boot.max_bytes == 1024 * 1024
    assert (directory.width, directory.height) == (800, 1280)
    assert profile.supports_custom_home_icons is False
    assert any("539.30.10.130" in note for note in profile.notes)
    assert any("120x120" in note for note in profile.notes)
