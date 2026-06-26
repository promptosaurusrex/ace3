// ACE3 keyboard navigation.
// Single shortcut: press `a` (when not typing) to focus the page's action bar.
// Once focused: Tab / arrow keys navigate between buttons, Enter activates.
// Also auto-focuses the first usable control inside any Bootstrap modal that opens.

(function () {
    "use strict";

    const FOCUS_KEY = "a";

    function findActionBar() {
        return document.querySelector("[data-action-bar]");
    }

    function isTypingTarget(el) {
        if (!el) return false;
        if (el.isContentEditable) return true;
        const tag = (el.tagName || "").toLowerCase();
        if (tag === "textarea" || tag === "select") return true;
        if (tag === "input") {
            const type = (el.getAttribute("type") || "text").toLowerCase();
            return !["checkbox", "radio", "button", "submit", "reset", "file"].includes(type);
        }
        return false;
    }

    function modalIsOpen() {
        return document.querySelector(".modal.show") !== null;
    }

    function actionBarItems(bar) {
        return Array.prototype.slice.call(
            bar.querySelectorAll("button, a.btn, [role='button']")
        ).filter(function (n) { return !n.disabled && n.offsetParent !== null; });
    }

    function focusActionBar() {
        const bar = findActionBar();
        if (!bar) return;
        const items = actionBarItems(bar);
        if (items.length) {
            items[0].focus();
            try { items[0].scrollIntoView({ behavior: "smooth", block: "nearest" }); } catch (e) {}
        }
    }

    document.addEventListener("keydown", function (e) {
        // arrow-key navigation while focused inside the action bar
        const bar = findActionBar();
        if (bar && (e.key === "ArrowLeft" || e.key === "ArrowRight")) {
            if (bar.contains(e.target) && !isTypingTarget(e.target)) {
                const items = actionBarItems(bar);
                if (items.length) {
                    let idx = items.indexOf(e.target);
                    if (idx === -1) idx = 0;
                    const dir = (e.key === "ArrowRight") ? 1 : -1;
                    const next = items[(idx + dir + items.length) % items.length];
                    e.preventDefault();
                    next.focus();
                }
                return;
            }
        }

        if (e.ctrlKey || e.metaKey || e.altKey) return;
        if (isTypingTarget(e.target)) return;
        if (modalIsOpen()) return;

        if ((e.key || "").toLowerCase() === FOCUS_KEY) {
            e.preventDefault();
            focusActionBar();
        }
    });

    // Auto-focus the first usable control inside any opened Bootstrap modal,
    // so the keyboard never lands on the modal backdrop with nothing selected.
    document.addEventListener("DOMContentLoaded", function () {
        if (!window.jQuery) return;
        jQuery(document).on("shown.bs.modal", function (e) {
            const modal = e.target;
            if (!modal) return;
            const candidates = modal.querySelectorAll(
                "textarea, " +
                "input:not([type='hidden']):not([type='submit']):not([type='button']):not([type='reset']):not([disabled]), " +
                "select:not([disabled])"
            );
            let target = null;
            for (let i = 0; i < candidates.length; i++) {
                const el = candidates[i];
                if (el.offsetParent === null) continue;
                if (el.getAttribute("aria-hidden") === "true") continue;
                target = el;
                break;
            }
            if (!target) return;
            try { target.focus(); } catch (err) {}
            if (target.setSelectionRange && (target.tagName === "TEXTAREA" ||
                (target.tagName === "INPUT" && /^(text|search|url|email|tel|password)?$/i.test(target.type || "text")))) {
                try {
                    const len = (target.value || "").length;
                    target.setSelectionRange(len, len);
                } catch (err) {}
            }
        });
    });
})();
