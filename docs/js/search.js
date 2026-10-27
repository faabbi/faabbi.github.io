(function () {
    "use strict";
    var input = document.getElementById("mjSearchInput");
    var form = document.getElementById("mjSearchForm");
    var status = document.getElementById("mjSearchStatus");
    var empty = document.querySelector(".notFind");
    var list = document.querySelector(".SideNav");
    var tagbar = document.getElementById("taglabel");
    var posts = [];
    var tags = [];
    var siteTitle = document.title.split(" - ").pop();
    document.getElementById("pathHome").setAttribute("d", IconList.home);
    function element(name, className, text) {
        var node = document.createElement(name);
        if (className) { node.className = className; }
        if (text !== undefined) { node.textContent = text; }
        return node;
    }
    function hashValue() {
        try { return decodeURIComponent(location.hash.slice(1)); } catch (e) { return location.hash.slice(1); }
    }
    function update() {
        var query = hashValue().trim();
        var isTag = tags.indexOf(query) !== -1;
        var all = !query || query === "All";
        var count = 0;
        posts.forEach(function (post) {
            var matches = all || (isTag ? post.labels.indexOf(query) !== -1 : (post.postTitle + " " + post.labels.join(" ")).toLocaleLowerCase().indexOf(query.toLocaleLowerCase()) !== -1);
            post.node.hidden = !matches;
            if (matches) { count++; }
        });
        input.value = all || isTag ? "" : query;
        status.textContent = (all ? "全部文章" : (isTag ? "标签：" : "搜索：") + query) + " · " + count + " 篇";
        empty.hidden = count !== 0;
        tagbar.querySelectorAll("button").forEach(function (button) {
            button.setAttribute("aria-pressed", String(button.dataset.tag === (all ? "All" : query)));
        });
        document.title = (all ? "文章与搜索" : query) + " - " + siteTitle;
    }
    function navigate(value) {
        var next = value ? "#" + encodeURIComponent(value) : "";
        if (location.hash === next) { update(); }
        else { location.hash = next; }
    }
    form.addEventListener("submit", function (event) { event.preventDefault(); navigate(input.value.trim()); });
    window.addEventListener("hashchange", update);
    fetch("postList.json").then(function (response) {
        if (!response.ok) { throw new Error("HTTP " + response.status); }
        return response.json();
    }).then(function (data) {
        var counts = {};
        Object.keys(data).forEach(function (key) {
            var post = data[key];
            if (!post || !Array.isArray(post.labels)) { return; }
            post.labels.forEach(function (tag) { counts[tag] = (counts[tag] || 0) + 1; });
            var row = element("a", "SideNav-item");
            row.href = post.postUrl;
            var center = element("div", "d-flex flex-items-center");
            var icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
            icon.setAttribute("class", "SideNav-icon octicon");
            icon.setAttribute("width", "16"); icon.setAttribute("height", "16"); icon.setAttribute("aria-hidden", "true");
            var path = document.createElementNS("http://www.w3.org/2000/svg", "path"); path.setAttribute("d", IconList.post); icon.appendChild(path);
            center.appendChild(icon); center.appendChild(element("span", "listTitle", post.postTitle));
            var labels = element("div", "listLabels");
            post.labels.forEach(function (tag) {
                var badge = element("span", "Label LabelName", tag);
                window.mjPaintLabel(badge, data.labelColorDict[tag]);
                labels.appendChild(badge);
            });
            var date = element("time", "Label LabelTime", post.createdDate); date.dateTime = post.createdDate; window.mjPaintLabel(date, post.dateLabelColor); labels.appendChild(date);
            row.appendChild(center); row.appendChild(labels); list.appendChild(row);
            post.node = row; posts.push(post);
        });
        tags = Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a]; });
        ["All"].concat(tags).forEach(function (tag) {
            var button = element("button", "Label", tag === "All" ? "全部" : tag);
            button.type = "button"; button.dataset.tag = tag;
            window.mjPaintLabel(button, tag === "All" ? "#000000" : data.labelColorDict[tag]);
            button.appendChild(element("span", "Counter", String(tag === "All" ? posts.length : counts[tag])));
            button.addEventListener("click", function () { navigate(tag === "All" ? "" : tag); });
            tagbar.appendChild(button);
        });
        update();
    }).catch(function () {
        status.textContent = "文章列表未能载入，请刷新重试，或回首页浏览。";
    });
})();
