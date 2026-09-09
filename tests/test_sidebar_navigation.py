import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
HTML = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
HARNESS = ROOT / "tests" / "sidebar_navigation_harness.html"
EDGE_CANDIDATES = (
    pathlib.Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    pathlib.Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
)


class SidebarNavigationStaticTest(unittest.TestCase):
    def test_sidebar_uses_flex_column_layout(self):
        sidebar_css = HTML.split(".sidebar {", 1)[1].split("}", 1)[0]
        self.assertIn("display: flex", sidebar_css)
        self.assertIn("flex-direction: column", sidebar_css)

    def test_header_brand_block_does_not_shrink(self):
        brand_css = HTML.split(".brand-block {", 1)[1].split("}", 1)[0]
        self.assertIn("flex: 0 0 auto", brand_css)

    def test_nav_is_the_single_scrollable_area(self):
        nav_css = HTML.split(".side-nav {", 1)[1].split("}", 1)[0]
        self.assertIn("flex: 1 1 auto", nav_css)
        self.assertIn("min-height: 0", nav_css)
        self.assertIn("overflow-y: auto", nav_css)
        self.assertIn("overflow-x: hidden", nav_css)
        self.assertIn("overscroll-behavior: contain", nav_css)
        self.assertIn("scrollbar-width: thin", nav_css)

    def test_nav_scrollbar_is_discreet_and_dark_themed(self):
        self.assertIn(".side-nav::-webkit-scrollbar {", HTML)
        self.assertIn("width: 6px", HTML)
        self.assertIn("scrollbar-color: rgba(255, 255, 255, .28) transparent", HTML)

    def test_no_fixed_pixel_height_on_nav(self):
        nav_css = HTML.split(".side-nav {", 1)[1].split("}", 1)[0]
        self.assertNotRegex(nav_css, r"height\s*:\s*\d+px")
        self.assertIn("min-height: 0", nav_css)

    def test_brand_block_lives_outside_scrollable_nav(self):
        aside_start = HTML.index('<aside class="sidebar">')
        nav_start = HTML.index('<nav class="side-nav"')
        nav_end = HTML.index("</nav>", nav_start)
        brand_markup_start = HTML.index('class="brand-block"', aside_start)
        self.assertLess(aside_start, brand_markup_start)
        self.assertLess(brand_markup_start, nav_start)
        self.assertNotIn("brand-block", HTML[nav_start:nav_end])

    def test_threat_intelligence_stays_inside_nav_list(self):
        nav_start = HTML.index('<nav class="side-nav"')
        nav_end = HTML.index("</nav>", nav_start)
        self.assertIn('data-nav-view="threat-intelligence"', HTML[nav_start:nav_end])
        self.assertNotIn('data-nav-view="threat-intelligence"', HTML[:nav_start])

    def test_active_nav_scrolls_into_view_via_helper(self):
        self.assertIn("function scrollActiveNavIntoView()", HTML)
        self.assertIn("scrollIntoView({ block: 'nearest', behavior: 'auto' })", HTML)
        show_view = HTML.split("function showView(", 1)[1]
        self.assertIn("scrollActiveNavIntoView();", show_view)


class SidebarNavigationBrowserHarnessTest(unittest.TestCase):
    def test_real_browser_sidebar_scroll_layout(self):
        edge = next((path for path in EDGE_CANDIDATES if path.exists()), None)
        if edge is None:
            self.skipTest("Microsoft Edge não está disponível")
        with tempfile.TemporaryDirectory(prefix="gmj-sidebar-edge-") as profile:
            completed = subprocess.run(
                [
                    str(edge),
                    "--headless=new",
                    "--disable-gpu",
                    "--disable-extensions",
                    "--no-first-run",
                    "--force-time-zone=America/Sao_Paulo",
                    "--allow-file-access-from-files",
                    "--window-size=1366,900",
                    "--virtual-time-budget=3000",
                    "--user-data-dir=%s" % profile,
                    "--dump-dom",
                    HARNESS.resolve().as_uri(),
                ],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
        self.assertEqual(
            completed.returncode,
            0,
            completed.stderr[-4000:],
        )
        self.assertIn(
            'data-status="passed"',
            completed.stdout,
            completed.stdout[-4000:],
        )
        self.assertIn("SIDEBAR_NAVIGATION_TESTS_OK", completed.stdout)


if __name__ == "__main__":
    unittest.main()
