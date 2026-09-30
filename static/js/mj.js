/* ==========================================================================
   MJ · 博客外观脚本
   1) 首次访问默认暗色主题
   2) 背景透明度滑块(0% = 背景图最清晰,100% = 只见主题底色)
   3) 首页副标题:每次打开随机一句 + 流光效果
   ========================================================================== */
(function () {
    "use strict";

    /* ---------- 20 条随机句子 ---------- */
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

    var LS_OPACITY = "mj_bg_opacity";
    var LS_PANEL = "mj_panel_open";
    var LS_THEME = "meek_theme";

    var root = document.documentElement;

    function store(key, value) {
        try { localStorage.setItem(key, value); } catch (e) { /* 隐私模式下忽略 */ }
    }

    function read(key) {
        try { return localStorage.getItem(key); } catch (e) { return null; }
    }

    /* ---------- 背景透明度 ---------- */
    var range = document.getElementById("mjOpacity");
    var valueLabel = document.getElementById("mjOpacityVal");

    function applyOpacity(raw) {
        var value = parseInt(raw, 10);
        if (isNaN(value)) { value = 0; }
        value = Math.max(0, Math.min(100, value));
        root.style.setProperty("--mj-bg-opacity", String(1 - value / 100));
        if (valueLabel) { valueLabel.textContent = value + "%"; }
        if (range && String(value) !== range.value) { range.value = String(value); }
        store(LS_OPACITY, String(value));
    }

    applyOpacity(read(LS_OPACITY) || 0);

    if (range) {
        range.addEventListener("input", function () { applyOpacity(range.value); });
    }

    /* ---------- 主题 ---------- */
    var THEME_ICON = { dark: "moon", light: "sun", auto: "sync" };
    var THEME_COLOR = { dark: "#00f0ff", light: "#ff5000", auto: "" };
    var THEME_UTTERANCES = { dark: "dark-blue", light: "github-light", auto: "preferred-color-scheme" };

    function syncThemeButtons() {
        var current = read(LS_THEME) || "dark";
        var buttons = document.querySelectorAll("[data-mj-theme]");
        for (var i = 0; i < buttons.length; i++) {
            buttons[i].classList.toggle("mj-active", buttons[i].getAttribute("data-mj-theme") === current);
        }
    }

    function setTheme(mode, persist) {
        if (!THEME_ICON[mode]) { mode = "dark"; }
        root.setAttribute("data-color-mode", mode);
        if (persist !== false) { store(LS_THEME, mode); }

        var icon = document.getElementById("themeSwitch");
        if (icon) {
            if (window.IconList && window.IconList[THEME_ICON[mode]]) {
                icon.setAttribute("d", window.IconList[THEME_ICON[mode]]);
            }
            if (icon.parentNode && icon.parentNode.style) {
                icon.parentNode.style.color = THEME_COLOR[mode];
            }
        }

        var frame = document.getElementsByClassName("utterances-frame")[0];
        if (frame && frame.contentWindow) {
            frame.contentWindow.postMessage(
                { type: "set-theme", theme: THEME_UTTERANCES[mode] },
                "https://utteranc.es"
            );
        }

        syncThemeButtons();
    }

    window.mjSetTheme = setTheme;

    var themeButtons = document.querySelectorAll("[data-mj-theme]");
    for (var b = 0; b < themeButtons.length; b++) {
        themeButtons[b].addEventListener("click", function () {
            setTheme(this.getAttribute("data-mj-theme"));
        });
    }

    /* 顶部那个太阳/月亮按钮走的是模板里的 modeSwitch(),点完要让面板同步 */
    if (typeof window.modeSwitch === "function") {
        var originalModeSwitch = window.modeSwitch;
        window.modeSwitch = function () {
            var result = originalModeSwitch.apply(this, arguments);
            syncThemeButtons();
            return result;
        };
    }

    syncThemeButtons();

    /* ---------- 外观面板开关 ---------- */
    var panel = document.getElementById("mjPanel");
    var toggle = document.getElementById("mjPanelToggle");
    var closeButton = document.getElementById("mjPanelClose");

    function setPanel(open) {
        if (!panel) { return; }
        panel.classList.toggle("mj-collapsed", !open);
        document.body.classList.toggle("mj-panel-open", !!open);
        store(LS_PANEL, open ? "1" : "0");
    }

    if (panel) {
        /* 宽屏默认展开(显眼),窄屏默认收起成右下角齿轮按钮,避免压住正文 */
        var savedPanel = read(LS_PANEL);
        var initialOpen = savedPanel === null ? window.innerWidth > 1400 : savedPanel !== "0";
        setPanel(initialOpen);
        if (toggle) { toggle.addEventListener("click", function () { setPanel(true); }); }
        if (closeButton) { closeButton.addEventListener("click", function () { setPanel(false); }); }
    }

    /* ---------- 当前页面标记(友链页要单独排版) ---------- */
    if (/\/link\.html$/i.test(location.pathname)) {
        document.body.classList.add("mj-friends");
    }

    /* ---------- 随机副标题 ---------- */
    var subtitle = document.getElementById("mjSubTitle");
    if (subtitle) {
        subtitle.textContent = QUOTES[Math.floor(Math.random() * QUOTES.length)];
        subtitle.classList.add("mj-ready");
    }

    /* ---------- 首次进站提示 ---------- */
    if (panel && read(LS_PANEL) === null) {
        var tip = document.createElement("div");
        tip.className = "mj-tip";
        tip.textContent = window.innerWidth > 1400 ? "右边可以调主题和背景透明度" : "右下角齿轮可以调主题和背景透明度";
        document.body.appendChild(tip);
        setTimeout(function () { tip.classList.add("mj-show"); }, 600);
        setTimeout(function () { tip.classList.remove("mj-show"); }, 5200);
        setTimeout(function () { if (tip.parentNode) { tip.parentNode.removeChild(tip); } }, 6000);
    }
})();
