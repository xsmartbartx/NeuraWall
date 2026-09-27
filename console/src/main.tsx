import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { Loading } from "./components/ui";
import { AuthProvider, ToastProvider, useAuth } from "./lib/hooks";
import { Alerts } from "./pages/Alerts";
import { Approvals } from "./pages/Approvals";
import { Audit } from "./pages/Audit";
import { Billing } from "./pages/Billing";
import { Bundles } from "./pages/Bundles";
import { Fleet } from "./pages/Fleet";
import { Flows } from "./pages/Flows";
import { ForcePasswordChange, Login } from "./pages/Login";
import { Overview } from "./pages/Overview";
import { Rules } from "./pages/Rules";
import { Settings } from "./pages/Settings";
import { Users } from "./pages/Users";
import "./styles.css";

try {
  document.documentElement.dataset.theme = localStorage.getItem("neurawall.theme") ?? "dark";
} catch { /* default theme */ }

function App() {
  const { me, ready } = useAuth();
  if (!ready) return <Loading what="Starting console" />;
  if (!me) return <Login />;
  if (me.must_change_password) return <ForcePasswordChange />;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="alerts/:alertId" element={<Alerts />} />
        <Route path="flows" element={<Flows />} />
        <Route path="approvals" element={<Approvals />} />
        <Route path="approvals/:draftId" element={<Approvals />} />
        <Route path="rules" element={<Rules />} />
        <Route path="bundles" element={<Bundles />} />
        <Route path="fleet" element={<Fleet />} />
        <Route path="audit" element={<Audit />} />
        <Route path="users" element={<Users />} />
        <Route path="billing" element={<Billing />} />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <ToastProvider>
        <AuthProvider>
          <App />
        </AuthProvider>
      </ToastProvider>
    </BrowserRouter>
  </StrictMode>,
);
