(() => {
  "use strict";

  const root = document.documentElement;
  const savedTheme = localStorage.getItem("gateway-theme");
  if (savedTheme === "light" || savedTheme === "dark") root.dataset.theme = savedTheme;
  const themeToggle = document.querySelector("[data-theme-toggle]");
  themeToggle?.addEventListener("click", () => {
    const currentlyDark = root.dataset.theme === "dark" || (
      !root.dataset.theme && window.matchMedia("(prefers-color-scheme: dark)").matches
    );
    const next = currentlyDark ? "light" : "dark";
    root.dataset.theme = next;
    localStorage.setItem("gateway-theme", next);
    themeToggle.setAttribute("aria-label", next === "dark" ? "切换到浅色主题" : "切换到深色主题");
  });

  const body = document.body;
  const shell = document.querySelector(".app-shell");
  const navToggle = document.querySelector("[data-nav-toggle]");
  const drawer = document.querySelector("#global-navigation");
  const drawerOpen = document.querySelector("[data-drawer-open]");
  let drawerTrigger = null;

  if (shell && window.innerWidth >= 1200) {
    const preference = localStorage.getItem("gateway-nav-mode") || "expanded";
    shell.dataset.nav = preference === "compact" ? "compact" : "expanded";
  }

  navToggle?.addEventListener("click", () => {
    if (!shell) return;
    const next = shell.dataset.nav === "compact" ? "expanded" : "compact";
    shell.dataset.nav = next;
    localStorage.setItem("gateway-nav-mode", next);
    navToggle.setAttribute("aria-label", next === "compact" ? "展开导航" : "收起导航");
    navToggle.setAttribute("title", next === "compact" ? "展开导航" : "收起导航");
  });

  function openDrawer(trigger) {
    drawerTrigger = trigger;
    body.dataset.drawer = "open";
    drawerOpen?.setAttribute("aria-expanded", "true");
    requestAnimationFrame(() => drawer?.querySelector("a, button")?.focus());
  }

  function closeDrawer() {
    delete body.dataset.drawer;
    drawerOpen?.setAttribute("aria-expanded", "false");
    drawerTrigger?.focus();
  }

  drawerOpen?.addEventListener("click", () => openDrawer(drawerOpen));
  document.querySelectorAll("[data-drawer-close]").forEach((node) => node.addEventListener("click", closeDrawer));
  drawer?.querySelectorAll("a.nav-item").forEach((link) => link.addEventListener("click", closeDrawer));

  const commandDialog = document.querySelector("[data-command-dialog]");
  const commandOpen = document.querySelector("[data-command-open]");
  const commandSearch = document.querySelector("[data-command-search]");
  const commandItems = [...document.querySelectorAll(".command-result")];
  const commandEmpty = document.querySelector("[data-command-empty]");
  let commandTrigger = null;

  function filterCommands() {
    const query = (commandSearch?.value || "").trim().toLocaleLowerCase();
    let visible = 0;
    commandItems.forEach((item) => {
      const match = !query || (item.dataset.commandText || "").toLocaleLowerCase().includes(query);
      item.hidden = !match;
      item.removeAttribute("data-active");
      if (match) visible += 1;
    });
    if (commandEmpty) commandEmpty.hidden = visible !== 0;
  }

  function openCommands(trigger) {
    if (!commandDialog) return;
    commandTrigger = trigger;
    commandDialog.showModal();
    if (commandSearch) {
      commandSearch.value = "";
      filterCommands();
      requestAnimationFrame(() => commandSearch.focus());
    }
  }

  commandOpen?.addEventListener("click", () => openCommands(commandOpen));
  commandSearch?.addEventListener("input", filterCommands);
  commandSearch?.addEventListener("keydown", (event) => {
    const visible = commandItems.filter((item) => !item.hidden);
    if (event.key === "ArrowDown" && visible.length) {
      event.preventDefault();
      visible[0].focus();
    }
    if (event.key === "Enter" && visible.length) {
      event.preventDefault();
      visible[0].click();
    }
  });
  commandItems.forEach((item, index) => item.addEventListener("keydown", (event) => {
    const visible = commandItems.filter((entry) => !entry.hidden);
    const current = visible.indexOf(item);
    if (event.key === "ArrowDown") {
      event.preventDefault();
      visible[(current + 1) % visible.length]?.focus();
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      if (current === 0) commandSearch?.focus();
      else visible[current - 1]?.focus();
    }
  }));
  commandDialog?.addEventListener("close", () => commandTrigger?.focus());

  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLocaleLowerCase() === "k") {
      event.preventDefault();
      openCommands(commandOpen);
      return;
    }
    if (event.key === "Escape" && body.dataset.drawer === "open") closeDrawer();
    if (event.key === "Tab" && body.dataset.drawer === "open" && drawer) {
      const focusable = [...drawer.querySelectorAll("a[href], button:not([disabled]), input:not([disabled])")];
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
  });

  const confirmDialog = document.querySelector("[data-confirm-dialog]");
  const confirmTitle = confirmDialog?.querySelector("[data-confirm-title]");
  const confirmMessage = confirmDialog?.querySelector("[data-confirm-message]");
  const confirmSubmit = confirmDialog?.querySelector("[data-confirm-submit]");
  let pendingForm = null;

  function setLoading(form) {
    const button = form.querySelector("button[type='submit']");
    if (!button || button.disabled) return false;
    button.dataset.originalText = button.textContent;
    button.setAttribute("aria-busy", "true");
    button.disabled = true;
    button.textContent = "处理中…";
    return true;
  }

  document.querySelectorAll("form[data-confirm-title]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (form.dataset.confirmed === "true") {
        setLoading(form);
        return;
      }
      event.preventDefault();
      pendingForm = form;
      if (confirmTitle) confirmTitle.textContent = form.dataset.confirmTitle || "确认操作";
      if (confirmMessage) confirmMessage.textContent = form.dataset.confirmMessage || "此操作会改变系统状态。";
      if (confirmSubmit) {
        confirmSubmit.textContent = form.dataset.confirmLabel || "确认";
        confirmSubmit.className = form.dataset.confirmKind === "danger" ? "button danger" : "button primary";
      }
      confirmDialog?.showModal();
      requestAnimationFrame(() => confirmDialog?.querySelector("[data-confirm-cancel]")?.focus());
    });
  });

  confirmDialog?.addEventListener("close", () => {
    if (confirmDialog.returnValue === "confirm" && pendingForm) {
      pendingForm.dataset.confirmed = "true";
      pendingForm.requestSubmit();
    } else {
      pendingForm?.querySelector("button[type='submit']")?.focus();
    }
    pendingForm = null;
  });

  document.querySelectorAll("form[data-loading-form]").forEach((form) => {
    form.addEventListener("submit", () => setLoading(form));
  });

  document.querySelectorAll("select[data-auto-submit]").forEach((select) => {
    select.addEventListener("change", () => select.form?.requestSubmit());
  });

  document.querySelectorAll("[data-table-filter]").forEach((input) => {
    const target = document.querySelector(input.dataset.tableFilter);
    const empty = document.querySelector(input.dataset.emptyTarget || "");
    const count = document.querySelector(input.dataset.countTarget || "");
    if (!target) return;
    const rows = [...target.querySelectorAll("[data-search]")];
    const apply = () => {
      const query = input.value.trim().toLocaleLowerCase();
      let visible = 0;
      rows.forEach((row) => {
        const match = !query || (row.dataset.search || "").toLocaleLowerCase().includes(query);
        row.hidden = !match;
        if (match) visible += 1;
      });
      if (count) count.textContent = `${visible} 项`;
      if (empty) empty.hidden = visible !== 0;
      const url = new URL(window.location.href);
      if (query) url.searchParams.set("q", input.value);
      else url.searchParams.delete("q");
      history.replaceState({}, "", url);
    };
    let timer;
    input.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(apply, 180);
    });
    apply();
  });

  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.querySelector(button.dataset.copy);
      if (!target) return;
      await navigator.clipboard.writeText(target.textContent || "");
      const previous = button.textContent;
      button.textContent = "已复制";
      setTimeout(() => { button.textContent = previous; }, 1600);
    });
  });

  document.querySelectorAll("details.details-menu").forEach((details) => {
    details.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        details.open = false;
        details.querySelector("summary")?.focus();
      }
    });
  });

  if (document.querySelector(".app-shell") && !location.hash) {
    requestAnimationFrame(() => document.querySelector("h1")?.focus({ preventScroll: true }));
  }
})();
