/* 登录 / 首次初始化。 */
"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const page = document.body.dataset.page;

  if (page === "login") {
    $("#loginForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const msg = $("#msg");
      msg.textContent = "";
      try {
        await api("POST", "/api/login", {
          username: $("#username").value.trim(),
          password: $("#password").value,
          code: $("#code").value.trim(),
        });
        location.href = "/";
      } catch (err) {
        if (err.error === "需要两步验证码") {
          // 展示验证码输入,聚焦
          $("#codeLabel").classList.remove("hidden");
          $("#code").focus();
          msg.textContent = "请输入两步验证码";
          return;
        }
        msg.textContent = err.status === 429 ? "尝试过于频繁,请稍后再试" : (err.error || "登录失败");
      }
    });
    // 未初始化时引导到 /setup
    api("GET", "/api/setup").then((s) => {
      if (s && s.initialized === false) location.href = "/setup";
    }).catch(() => {});
  }

  if (page === "setup") {
    $("#setupForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const msg = $("#msg");
      msg.textContent = "";
      if ($("#password").value !== $("#password2").value) {
        msg.textContent = "两次输入的密码不一致";
        return;
      }
      try {
        await api("POST", "/api/setup", {
          username: $("#username").value.trim(),
          password: $("#password").value,
        });
        alert("管理员已创建,请登录");
        location.href = "/login";
      } catch (err) {
        msg.textContent = err.error || "初始化失败";
      }
    });
  }
});
