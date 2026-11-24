import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import './components/arc/foundation.css';
import './styles.css';
import { PublicLayout, RequireAuth } from './components/ui';
import { Landing, ServicesPage, ServiceDetail, IndustriesPage, AboutPage, CasesPage, CaseDetail } from './pages/Public';
import { CareersPage, CareerDetail, ContactPage, QuotePage, TalentPage, LegalPage } from './pages/Public2';
import { LoginPage, RegisterPage, ForgotPage, ResetPage } from './pages/Auth';
import { PortalLayout, Dashboard, ProjectsPage, ProjectDetail, TeamPage, RequestsPage, DocumentsPage, TicketsPage, InvoicesPage, ActivityPage, ProfilePage } from './pages/Portal';
import { OperationsLayout, OpsSummary, OpsClients, OpsProjects, OpsLeads, OpsQuotes, OpsApplications, OpsConsultants, OpsTickets, OpsInvoices } from './pages/Operations';

const P = ({ children }: { children: React.ReactNode }) => <PublicLayout>{children}</PublicLayout>;
createRoot(document.getElementById('root')!).render(
  <React.StrictMode><BrowserRouter><Routes>
    <Route path="/" element={<P><Landing /></P>} />
    <Route path="/servicios" element={<P><ServicesPage /></P>} />
    <Route path="/servicios/:slug" element={<P><ServiceDetail /></P>} />
    <Route path="/industrias" element={<P><IndustriesPage /></P>} />
    <Route path="/nosotros" element={<P><AboutPage /></P>} />
    <Route path="/casos-de-exito" element={<P><CasesPage /></P>} />
    <Route path="/casos-de-exito/:slug" element={<P><CaseDetail /></P>} />
    <Route path="/carreras" element={<P><CareersPage /></P>} />
    <Route path="/carreras/:slug" element={<P><CareerDetail /></P>} />
    <Route path="/contacto" element={<P><ContactPage /></P>} />
    <Route path="/solicitar-propuesta" element={<P><QuotePage /></P>} />
    <Route path="/talento" element={<P><TalentPage /></P>} />
    <Route path="/privacidad" element={<P><LegalPage kind="privacidad" /></P>} />
    <Route path="/terminos" element={<P><LegalPage kind="terminos" /></P>} />
    <Route path="/login" element={<LoginPage />} />
    <Route path="/registro" element={<RegisterPage />} />
    <Route path="/recuperar-contrasena" element={<ForgotPage />} />
    <Route path="/restablecer-contrasena" element={<ResetPage />} />
    <Route path="/portal" element={<RequireAuth><PortalLayout /></RequireAuth>}>
      <Route index element={<Dashboard />} />
      <Route path="proyectos" element={<ProjectsPage />} />
      <Route path="proyectos/:id" element={<ProjectDetail />} />
      <Route path="equipo" element={<TeamPage />} />
      <Route path="solicitudes" element={<RequestsPage />} />
      <Route path="documentos" element={<DocumentsPage />} />
      <Route path="tickets" element={<TicketsPage />} />
      <Route path="facturacion" element={<InvoicesPage />} />
      <Route path="actividad" element={<ActivityPage />} />
      <Route path="perfil" element={<ProfilePage />} />
    </Route>
    <Route path="/operations" element={<RequireAuth><OperationsLayout /></RequireAuth>}>
      <Route index element={<OpsSummary />} />
      <Route path="clientes" element={<OpsClients />} />
      <Route path="proyectos" element={<OpsProjects />} />
      <Route path="leads" element={<OpsLeads />} />
      <Route path="solicitudes" element={<OpsQuotes />} />
      <Route path="candidaturas" element={<OpsApplications />} />
      <Route path="colaboradores" element={<OpsConsultants />} />
      <Route path="tickets" element={<OpsTickets />} />
      <Route path="facturas" element={<OpsInvoices />} />
    </Route>
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes></BrowserRouter></React.StrictMode>);
