/* PRE ADV API client helper for login.html and area-clienti.html */
window.PREADV_API_BASE = window.PREADV_API_BASE || "https://YOUR-RAILWAY-APP.up.railway.app";

window.PREADV_API = {
  async request(path, options = {}) {
    const res = await fetch(window.PREADV_API_BASE + path, {
      credentials: "include",
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
      ...options
    });
    const data = await res.json().catch(() => ({}));
    if(!res.ok) throw new Error(data.error || "Request failed");
    return data;
  },

  clientRegister(payload) {
    return this.request("/api/auth/client/register", {
      method: "POST",
      body: JSON.stringify(payload)
    });
  },

  clientLogin(email, password) {
    return this.request("/api/auth/client/login", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });
  },

  adminLogin(email, password) {
    return this.request("/api/auth/admin/login", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });
  },

  me() {
    return this.request("/api/me");
  },

  logout() {
    return this.request("/api/auth/logout", { method: "POST" });
  },

  clientDashboard() {
    return this.request("/api/client/dashboard");
  },

  createClientRequest(payload) {
    return this.request("/api/client/requests", {
      method: "POST",
      body: JSON.stringify(payload)
    });
  },

  sendClientMessage(text) {
    return this.request("/api/client/messages", {
      method: "POST",
      body: JSON.stringify({ text })
    });
  },

  createLead(payload) {
    return this.request("/api/leads", {
      method: "POST",
      body: JSON.stringify(payload)
    });
  },

  adminDashboard() {
    return this.request("/api/admin/dashboard");
  },

  adminClients() {
    return this.request("/api/admin/clients");
  },

  adminCreateDelivery(payload) {
    return this.request("/api/admin/deliveries", {
      method: "POST",
      body: JSON.stringify(payload)
    });
  },

  adminSendMessage(clientId, text) {
    return this.request("/api/admin/messages", {
      method: "POST",
      body: JSON.stringify({ clientId, text })
    });
  }
};
