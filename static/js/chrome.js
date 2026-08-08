/* Page furniture: theme toggle, mobile nav, and the in-view nav highlight.
 *
 * Everything here runs after the document has parsed, so unlike the pre-paint
 * theme script in base.html it does not need to be inline. Keeping it in a file
 * lets the Content-Security-Policy stay at script-src 'self' plus a single
 * nonce, rather than opening up to inline script generally. */
(function () {
    "use strict";

    /* ---------------------------------------------------------- theme */
    var root = document.documentElement;
    document.getElementById("themeToggle").addEventListener("click", function () {
        var dark = root.dataset.theme !== "dark";
        root.classList.add("theme-switching");
        root.dataset.theme = dark ? "dark" : "light";
        try { localStorage.setItem("filecrypt-theme", dark ? "dark" : "light"); } catch (e) {}
        // Two frames: one to apply the new colours, one to let them paint
        // before transitions are allowed back.
        requestAnimationFrame(function () {
            requestAnimationFrame(function () {
                root.classList.remove("theme-switching");
            });
        });
    });

    /* ------------------------------------------------- mobile menu */
    var nav = document.getElementById("nav");
    var navToggle = document.getElementById("navToggle");
    navToggle.addEventListener("click", function () {
        var open = nav.dataset.open !== "true";
        nav.dataset.open = open ? "true" : "false";
        navToggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    nav.addEventListener("click", function (e) {
        if (e.target.closest(".nav-link")) {
            nav.dataset.open = "false";
            navToggle.setAttribute("aria-expanded", "false");
        }
    });

    /* --------------------------------- highlight the section in view */
    var links = Array.prototype.slice.call(nav.querySelectorAll(".nav-link"));
    var targets = links
        .map(function (link) { return document.querySelector(link.getAttribute("href")); })
        .filter(Boolean);

    if ("IntersectionObserver" in window && targets.length) {
        var observer = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (!entry.isIntersecting) return;
                links.forEach(function (link) {
                    link.classList.toggle(
                        "is-active",
                        link.getAttribute("href") === "#" + entry.target.id
                    );
                });
            });
        }, { rootMargin: "-45% 0px -50% 0px" });
        targets.forEach(function (t) { observer.observe(t); });
    }
})();
