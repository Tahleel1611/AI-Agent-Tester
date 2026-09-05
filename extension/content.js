// This file is injected on demand by background.js, after the user clicks Scan.
function extractPageContext() {
  const elements = [...document.body.querySelectorAll("h1, h2, h3, p, a, button, form, input, textarea, img")]
    .slice(0, 150)
    .map((element) => ({
      tag: element.tagName.toLowerCase(),
      id: element.id || null,
      classes: [...element.classList].slice(0, 5),
      text: (element.innerText || element.getAttribute("aria-label") || element.alt || "").trim().slice(0, 280),
      hasInlineHandler: [...element.attributes].some((attribute) => attribute.name.startsWith("on"))
    }));

  return {
    url: location.href,
    title: document.title,
    text_content: (document.body.innerText || "").trim().slice(0, 20000),
    dom_structure: elements,
    captured_at: new Date().toISOString()
  };
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type !== "REQUEST_PAGE_CONTEXT") return;
  try {
    const payload = extractPageContext();
    chrome.runtime.sendMessage({ type: "DOM_PAYLOAD", payload });
    sendResponse({ ok: true, payload });
  } catch (error) {
    sendResponse({ ok: false, error: error.message });
  }
});
