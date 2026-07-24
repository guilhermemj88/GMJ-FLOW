import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")


class FrontendThemeBootstrapTest(unittest.TestCase):
    def test_theme_is_applied_before_stylesheets_to_avoid_white_flash(self):
        bootstrap = HTML.index("const storageKey = 'gmjFlowAppearanceTheme'")
        bootstrap_css = HTML.index("bootstrap@5.3.3")
        app_styles = HTML.index("<style>")
        self.assertLess(bootstrap, bootstrap_css)
        self.assertLess(bootstrap, app_styles)
        self.assertIn("document.documentElement.dataset.theme = resolved", HTML[bootstrap:bootstrap_css])

    def test_auto_theme_uses_prefers_color_scheme(self):
        self.assertIn("window.matchMedia?.('(prefers-color-scheme: dark)').matches", HTML)
        self.assertIn("media.addEventListener('change', handler)", HTML)
        self.assertIn("document.documentElement.dataset.themePreference === 'auto'", HTML)

    def test_preference_is_persisted_without_removing_other_keys(self):
        self.assertIn("localStorage.setItem(APPEARANCE_THEME_KEY, selected)", HTML)
        self.assertIn("localStorage.getItem(APPEARANCE_THEME_KEY)", HTML)
        self.assertNotIn("localStorage.clear()", HTML)
        self.assertNotIn("localStorage.removeItem(APPEARANCE_THEME_KEY)", HTML)


class FrontendThemeConfigurationTest(unittest.TestCase):
    def test_system_page_exposes_all_theme_choices(self):
        self.assertIn('id="systemAppearancePanel"', HTML)
        self.assertIn('id="appearanceTheme"', HTML)
        for value, label in (
            ("auto", "Automático / Sistema"),
            ("light", "Claro"),
            ("dark", "Escuro"),
            ("noc-dark", "GMJ Dark / NOC Dark"),
        ):
            self.assertIn(f'<option value="{value}">{label}</option>', HTML)

    def test_theme_switch_does_not_reload_page(self):
        start = HTML.index("function setAppearanceTheme(")
        end = HTML.index("function initializeAppearanceTheme(", start)
        source = HTML[start:end]
        self.assertIn("document.documentElement.dataset.theme = resolved", source)
        self.assertNotIn("location.reload", source)
        self.assertNotIn("window.location", source)


class FrontendThemeTokensTest(unittest.TestCase):
    def test_semantic_tokens_are_declared(self):
        for token in (
            "--background:",
            "--surface:",
            "--surface-secondary:",
            "--text-primary:",
            "--text-secondary:",
            "--border:",
            "--accent:",
            "--success:",
            "--warning:",
            "--danger:",
            "--map-background:",
            "--map-label:",
            "--chart-grid:",
        ):
            self.assertIn(token, HTML)

    def test_light_dark_and_noc_dark_token_sets_exist(self):
        self.assertIn(":root {", HTML)
        self.assertIn('html[data-theme="dark"]', HTML)
        self.assertIn('html[data-theme="noc-dark"]', HTML)

    def test_tokens_cover_main_ui_surfaces(self):
        for selector in (
            "html[data-theme] .sidebar",
            "html[data-theme] .panel",
            "html[data-theme] .metric-card",
            "html[data-theme] .table",
            "html[data-theme] .form-control",
            "html[data-theme] .form-select",
            "html[data-theme] .gmj-dialog",
            "html[data-theme] .btn-success",
            "html[data-theme] .alert",
            "html[data-theme] .help-tip",
        ):
            self.assertIn(selector, HTML)

    def test_charts_use_theme_tokens(self):
        self.assertIn("function refreshChartsForTheme()", HTML)
        self.assertIn("themeColor('chart-grid'", HTML)
        self.assertIn("themeColor('border'", HTML)
        self.assertIn("themeColor('text-secondary'", HTML)

    def test_geo_flow_map_follows_theme_and_switches_tiles(self):
        self.assertIn("setTheme(theme)", HTML)
        self.assertIn("light_all/{z}/{x}/{y}{r}.png", HTML)
        self.assertIn("dark_all/{z}/{x}/{y}{r}.png", HTML)
        self.assertIn("globalGeoFlowMap?.setTheme(resolved)", HTML)
        self.assertIn("dashboardGeoFlowMap?.setTheme(resolved)", HTML)
        self.assertIn("--geo-bg: var(--map-background", HTML)
        self.assertIn("--geo-ink: var(--map-label", HTML)


if __name__ == "__main__":
    unittest.main()
