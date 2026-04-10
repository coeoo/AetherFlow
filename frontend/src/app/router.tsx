import type { RouteObject } from "react-router-dom";

import { AnnouncementRunDetailPage } from "../routes/AnnouncementRunDetailPage";
import { AnnouncementSourcesPage } from "../routes/AnnouncementSourcesPage";
import { AnnouncementWorkbenchPage } from "../routes/AnnouncementWorkbenchPage";
import { CVERunDetailPage } from "../routes/CVERunDetailPage";
import { CVELookupPage } from "../routes/CVELookupPage";
import { DeliveryCenterPage } from "../routes/DeliveryCenterPage";
import { HomePage } from "../routes/HomePage";
import { SystemHealthPage } from "../routes/SystemHealthPage";
import { TaskCenterPage } from "../routes/TaskCenterPage";

export const routes: RouteObject[] = [
  { path: "/", element: <HomePage /> },
  { path: "/cve", element: <CVELookupPage /> },
  { path: "/cve/runs/:runId", element: <CVERunDetailPage /> },
  { path: "/announcements", element: <AnnouncementWorkbenchPage /> },
  { path: "/announcements/sources", element: <AnnouncementSourcesPage /> },
  { path: "/announcements/runs/:runId", element: <AnnouncementRunDetailPage /> },
  { path: "/deliveries", element: <DeliveryCenterPage /> },
  { path: "/system/tasks", element: <TaskCenterPage /> },
  { path: "/system/health", element: <SystemHealthPage /> },
];
