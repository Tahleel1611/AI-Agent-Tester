const API_URL = "http://127.0.0.1:8000/scan";

const mockBugs = [
  { category: "Security", severity: "high", title: "Potential reflected input exposure", description: "Page text includes user-controlled content that should be encoded before rendering." },
  { category: "UI/UX", severity: "medium", title: "Image accessibility gap", description: "One or more image elements appear to be missing descriptive alternative text." },
  { category: "Logic", severity: "low", title: "Form validation should be reviewed", description: "A form was detected; validate client-side rules against server-side enforcement." }
];

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "DOM_PAYLOAD") {
    console.debug("AI Web Tester received page context", { tabId: sender.tab?.id, url: message.payload?.url });
    return;
  }

  if (message.type !== "SCAN_CURRENT_TAB") return;
  scanCurrentTab().then(sendResponse).catch((error) => sendResponse({ ok: false, error: error.message }));
  return true;
});

async function scanCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !tab.url?.startsWith("http")) {
    throw new Error("Open a regular HTTP or HTTPS webpage before scanning.");
  }

  await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
  const contextResponse = await chrome.tabs.sendMessage(tab.id, { type: "REQUEST_PAGE_CONTEXT" });
  if (!contextResponse?.ok) throw new Error(contextResponse?.error || "Could not read page context.");

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(contextResponse.payload)
    });
    if (!response.ok) throw new Error(`API returned ${response.status}`);
    const data = await response.json();
    return { ok: true, bugs: data.bugs || data, usedMockData: false };
  } catch (error) {
    console.warn("AI Web Tester API unavailable; using local mock data.", error);
    return { ok: true, bugs: mockBugs, usedMockData: true };
  }
}
