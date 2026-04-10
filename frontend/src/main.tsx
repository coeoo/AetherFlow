import React from "react";
import ReactDOM from "react-dom/client";
import { RouterProvider, createBrowserRouter } from "react-router-dom";
import "@fontsource/manrope";

import { AppProviders } from "./app/providers";
import { routes } from "./app/router";
import "./styles/global.css";

const router = createBrowserRouter(routes, {
  future: {
    v7_startTransition: true,
  },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <AppProviders>
      <RouterProvider
        router={router}
        future={{
          v7_startTransition: true,
        }}
      />
    </AppProviders>
  </React.StrictMode>,
);
