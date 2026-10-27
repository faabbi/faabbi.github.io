(function () {
    "use strict";
    var QUOTES = [
        "人生这么长，不一直学怎么行呢？",
        "靶场打不完，但每一台都算数。",
        "今天比昨天多懂一点，就够了。",
        "漏洞藏在细节里，成长也是。",
        "慢一点没关系，别停下来就行。",
        "打点靠运气，拿权靠积累。",
        "记录下来的经验，才是自己的。",
        "复现一遍，胜过读十遍。",
        "不懂就拆开看，看完就懂了。",
        "别怕失败，怕的是不复盘。",
        "信息收集做得越细，路走得越稳。",
        "手上有活，心里不慌。",
        "每一个被忽略的细节，都是一条路。",
        "把复杂的问题拆小，就没有难题。",
        "坚持写 WP 的人，运气都不会太差。",
        "工具会过时，方法论不会。",
        "越是枯燥的基础，越是锋利的刀。",
        "世界很大，慢慢来，比较快。",
        "先跑通，再跑快，最后跑稳。",
        "你现在的每一步，都是以后的底气。"
    ];
    var subtitle = document.getElementById("mjSubTitle");
    if (subtitle) {
        subtitle.textContent = QUOTES[Math.floor(Math.random() * QUOTES.length)];
        subtitle.classList.add("mj-ready");
    }
    function paintLabel(node, color) {
        if (!/^#[0-9a-f]{6}$/i.test(color)) { return; }
        var rgb = [1, 3, 5].map(function (start) {
            var channel = parseInt(color.slice(start, start + 2), 16) / 255;
            return channel <= 0.04045 ? channel / 12.92 : Math.pow((channel + 0.055) / 1.055, 2.4);
        });
        var luminance = .2126 * rgb[0] + .7152 * rgb[1] + .0722 * rgb[2];
        node.style.setProperty("--mj-label-bg", color);
        node.style.setProperty("--mj-label-fg", luminance > .179 ? "#000000" : "#ffffff");
    }
    window.mjPaintLabel = paintLabel;
    document.querySelectorAll(".Label").forEach(function (label) {
        paintLabel(label, label.style.getPropertyValue("--mj-label-bg").trim());
    });

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
