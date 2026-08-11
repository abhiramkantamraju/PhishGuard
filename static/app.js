/*
 * Progressive enhancements shared by every page: theme toggle, live character
 * count, one-click sample emails, delete confirmation.
 *
 * Everything here is optional by design — with JavaScript disabled the form
 * still submits, the history table still renders and deletes still work. The
 * only behaviour that genuinely needs JS is the background link check, which
 * lives in result.html because it needs the scan id and CSRF token.
 */
(function () {
    "use strict";

    var root = document.documentElement;

    /* --- Theme toggle -------------------------------------------------- */

    function prefersDark() {
        return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    }

    function currentTheme() {
        var theme = root.dataset.theme;
        if (theme === "dark" || theme === "light") { return theme; }
        return prefersDark() ? "dark" : "light";
    }

    var toggle = document.getElementById("theme-toggle");
    if (toggle) {
        toggle.addEventListener("click", function () {
            var next = currentTheme() === "dark" ? "light" : "dark";
            root.dataset.theme = next;
            try {
                localStorage.setItem("phishguard-theme", next);
            } catch (error) { /* private mode: the choice just won't persist */ }
        });
    }

    /* --- Character counter --------------------------------------------- */

    var textarea = document.getElementById("email_text");
    var counter = document.getElementById("char-count");
    if (textarea && counter) {
        var maxLength = parseInt(counter.dataset.max, 10) || 0;

        var updateCount = function () {
            var used = textarea.value.length;
            counter.textContent = used.toLocaleString() + " / " + maxLength.toLocaleString() + " characters";
            counter.classList.toggle("char-count--over", maxLength > 0 && used > maxLength);
        };

        textarea.addEventListener("input", updateCount);
        updateCount();
    }

    /* --- Sample emails ------------------------------------------------- */

    document.querySelectorAll("[data-sample]").forEach(function (button) {
        button.addEventListener("click", function () {
            if (!textarea) { return; }
            textarea.value = button.dataset.sample;
            textarea.dispatchEvent(new Event("input"));
            textarea.focus();
            textarea.setSelectionRange(0, 0);
            textarea.scrollTop = 0;
        });
    });

    /* --- Delete confirmation ------------------------------------------- */

    document.querySelectorAll("form[data-confirm]").forEach(function (form) {
        form.addEventListener("submit", function (event) {
            if (!window.confirm(form.dataset.confirm)) {
                event.preventDefault();
            }
        });
    });
})();
