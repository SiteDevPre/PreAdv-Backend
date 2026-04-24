/* PRE ADV backend tracker — put before </body> in index.html */
(function(){
  const API_BASE = window.PREADV_API_BASE || "https://YOUR-RAILWAY-APP.up.railway.app";
  const VISITOR_KEY = "preadv_visitor_id";
  function id(){ return "v_" + Math.random().toString(36).slice(2) + Date.now().toString(36); }
  let visitorId = localStorage.getItem(VISITOR_KEY);
  if(!visitorId){ visitorId = id(); localStorage.setItem(VISITOR_KEY, visitorId); }

  function post(path, body){
    try{
      fetch(API_BASE + path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(body)
      }).catch(function(){});
    }catch(e){}
  }

  const params = new URLSearchParams(location.search);
  post("/api/track/visit", {
    visitorId,
    path: location.pathname,
    title: document.title,
    referrer: document.referrer || "",
    utmSource: params.get("utm_source") || "",
    utmMedium: params.get("utm_medium") || "",
    utmCampaign: params.get("utm_campaign") || ""
  });

  document.addEventListener("click", function(e){
    const el = e.target.closest && e.target.closest("a,button");
    if(!el) return;
    const href = el.href || "";
    const label = (el.innerText || el.getAttribute("aria-label") || "").trim().slice(0,120);
    let type = "click";
    if(href.includes("wa.me") || /whatsapp/i.test(label)) type = "whatsapp";
    if(href.includes("mailto:")) type = "email";
    if(href.includes("login")) type = "login";
    post("/api/track/click", { visitorId, path: location.pathname, label, href, type });
  }, true);
})();
