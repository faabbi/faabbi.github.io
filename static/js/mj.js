(function () {
    "use strict";
    var root = document.documentElement;
    function read(key) { try { return localStorage.getItem(key); } catch (e) { return null; } }
    function store(key, value) { try { localStorage.setItem(key, value); } catch (e) {} }
    var systemTheme = matchMedia("(prefers-color-scheme: dark)");
    var currentTheme = root.getAttribute("data-mj-theme") || "dark";
    function setTheme(mode) {
        if (["dark", "light", "auto"].indexOf(mode) === -1) { mode = "dark"; }
        currentTheme = mode;
        var resolved = mode === "auto" ? (systemTheme.matches ? "dark" : "light") : mode;
        root.setAttribute("data-mj-theme", mode);
        root.setAttribute("data-color-mode", resolved);
        store("meek_theme", mode);
        document.querySelectorAll("[data-mj-theme]").forEach(function (button) {
            if (button === root) { return; }
            var selected = button.getAttribute("data-mj-theme") === mode;
            button.classList.toggle("mj-active", selected);
            button.setAttribute("aria-pressed", String(selected));
        });
        var icon = document.getElementById("themeSwitch");
        var iconName = mode === "auto" ? "sync" : (mode === "dark" ? "moon" : "sun");
        if (icon && window.IconList) { icon.setAttribute("d", window.IconList[iconName]); }
        var frame = document.querySelector(".utterances-frame");
        if (frame && frame.contentWindow) {
            frame.contentWindow.postMessage({ type: "set-theme", theme: resolved === "dark" ? "dark-blue" : "github-light" }, "https://utteranc.es");
        }
    }
    window.mjSetTheme = setTheme;
    document.querySelectorAll("button[data-mj-theme]").forEach(function (button) {
        button.addEventListener("click", function () { setTheme(button.getAttribute("data-mj-theme")); });
    });
    setTheme(currentTheme);
    systemTheme.addEventListener("change", function () { if (currentTheme === "auto") { setTheme("auto"); } });

    var range = document.getElementById("mjOpacity");
    var valueLabel = document.getElementById("mjOpacityVal");
    function applyOpacity(raw) {
        var value = Number(raw);
        if (!Number.isFinite(value)) { value = 60; }
        value = Math.max(0, Math.min(100, value));
        root.style.setProperty("--mj-bg-opacity", String(1 - value / 100));
        if (range) { range.value = String(value); }
        if (valueLabel) { valueLabel.textContent = value + "%"; }
        store("mj_bg_opacity", String(value));
    }
    var savedOpacity = read("mj_bg_opacity");
    applyOpacity(savedOpacity === null ? 60 : savedOpacity);
    if (range) { range.addEventListener("input", function () { applyOpacity(range.value); }); }

    var panel = document.getElementById("mjPanel");
    var toggle = document.getElementById("mjPanelToggle");
    var close = document.getElementById("mjPanelClose");
    function setPanel(open, restoreFocus) {
        if (!panel || !toggle) { return; }
        panel.hidden = !open;
        toggle.setAttribute("aria-expanded", String(open));
        if (open && close) { close.focus(); }
        if (!open && restoreFocus) { toggle.focus(); }
    }
    if (panel && toggle) {
        toggle.hidden = false;
        toggle.addEventListener("click", function () { setPanel(panel.hidden, false); });
        close.addEventListener("click", function () { setPanel(false, true); });
        document.addEventListener("keydown", function (event) {
            if (event.key === "Escape" && !panel.hidden) { setPanel(false, true); }
        });
        document.addEventListener("click", function (event) {
            if (!panel.hidden && !panel.contains(event.target) && !toggle.contains(event.target)) { setPanel(false, false); }
        });
    }
    if (document.getElementById("postBody")) { document.body.classList.add("mj-post"); }
    if (/\/link\.html$/i.test(location.pathname)) { document.body.classList.add("mj-friends"); }
    function markNavigation() {
        document.querySelectorAll("#mjNav a").forEach(function (link) {
            var url = new URL(link.href, location.href);
            var home = url.pathname === "/" && (/^\/(index\.html|page\d+\.html)?$/).test(location.pathname);
            var active = url.origin === location.origin && (home || (url.pathname === location.pathname && (!url.hash || url.hash === location.hash)));
            if (active) { link.setAttribute("aria-current", "page"); }
            else { link.removeAttribute("aria-current"); }
        });
    }
    markNavigation();
    window.addEventListener("hashchange", markNavigation);
})();
