"use strict";

const navToggle = document.querySelector(".nav-toggle");
const siteNav = document.querySelector("#site-nav");

if (navToggle && siteNav) {
  navToggle.addEventListener("click", () => {
    const open = navToggle.getAttribute("aria-expanded") === "true";
    navToggle.setAttribute("aria-expanded", String(!open));
    siteNav.classList.toggle("is-open", !open);
  });
}

document.querySelectorAll("form[data-confirm]").forEach((form) => {
  form.addEventListener("submit", (event) => {
    if (!window.confirm(form.dataset.confirm || "진행할까요?")) {
      event.preventDefault();
    }
  });
});

const imageInput = document.querySelector("[data-image-input]");
const imagePreview = document.querySelector("#image-preview");

if (imageInput && imagePreview) {
  imageInput.addEventListener("change", () => {
    const [file] = imageInput.files;
    if (!file) return;
    const image = document.createElement("img");
    image.alt = "선택한 상품 사진 미리보기";
    image.src = URL.createObjectURL(file);
    image.addEventListener("load", () => URL.revokeObjectURL(image.src), { once: true });
    imagePreview.replaceChildren(image);
  });
}

const chatPanel = document.querySelector("#global-chat");
const chatMessages = document.querySelector("#chat-messages");
const chatForm = document.querySelector("#global-chat-form");
const chatFeedback = document.querySelector("#chat-feedback");

function formatChatTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return new Intl.DateTimeFormat("ko-KR", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function appendChatMessage(message) {
  if (!chatMessages || chatMessages.querySelector(`[data-message-id="${message.id}"]`)) return;
  document.querySelector("#chat-empty")?.remove();

  const article = document.createElement("article");
  article.className = "chat-message";
  article.dataset.messageId = String(message.id);

  const avatar = document.createElement("div");
  avatar.className = "avatar";
  avatar.textContent = String(message.display_name || "?").slice(0, 1);

  const content = document.createElement("div");
  const meta = document.createElement("p");
  const author = document.createElement("strong");
  const time = document.createElement("time");
  const body = document.createElement("span");
  author.textContent = message.display_name;
  time.textContent = formatChatTime(message.created_at);
  body.textContent = message.body;
  meta.append(author, time);
  content.append(meta, body);
  article.append(avatar, content);
  chatMessages.append(article);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

if (
  chatPanel &&
  chatMessages &&
  chatPanel.dataset.canStream === "true" &&
  "EventSource" in window
) {
  const lastId = chatPanel.dataset.lastId || "0";
  const stream = new EventSource(`/api/chat/stream?after=${encodeURIComponent(lastId)}`);
  stream.onmessage = (event) => {
    try {
      appendChatMessage(JSON.parse(event.data));
    } catch {
      // Ignore malformed server events without breaking the stream.
    }
  };
}

if (chatForm) {
  chatForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = chatForm.querySelector("button[type='submit']");
    const bodyInput = chatForm.querySelector("[name='body']");
    submit.disabled = true;
    if (chatFeedback) chatFeedback.textContent = "";
    try {
      const response = await fetch(chatForm.action, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
        body: new URLSearchParams(new FormData(chatForm)),
      });
      if (!response.ok) {
        const payload = await response.text();
        throw new Error(payload.includes("너무") ? "메시지를 너무 빠르게 보내고 있어요." : "메시지를 보내지 못했습니다.");
      }
      bodyInput.value = "";
      bodyInput.focus();
    } catch (error) {
      if (chatFeedback) chatFeedback.textContent = error.message;
    } finally {
      submit.disabled = false;
    }
  });
}
