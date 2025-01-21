import { Box } from "@mui/material";
import React, { useEffect } from "react";
import { ErrorBoundary } from "react-error-boundary";
import { useDispatch, useSelector } from "react-redux";
import { useLocation, useNavigate } from "react-router-dom";

import { useSkipUntilAuthTokenIsReady } from "../../hooks/auth";
import { useTryLoginMutation } from "../../services/tcApi";
import { setAuthToken } from "../../slices/auth";
import { mainMaxWidth } from "../../utils/const";
import { auth } from "../../utils/firebase";

import { AppBar } from "./AppBar";
import { AppFallback } from "./AppFallback";
import { Drawer } from "./Drawer";
import { Main } from "./Main";
import { OutletWithCheckedParams } from "./OutletWithCheckedParams";

export function App() {
  const skip = useSkipUntilAuthTokenIsReady();

  const dispatch = useDispatch();
  const system = useSelector((state) => state.system);
  const location = useLocation();
  const navigate = useNavigate();

  const [tryLogin] = useTryLoginMutation();

  useEffect(() => {
    if (!skip) return; // auth token is ready
    const _checkToken = async () => {
      try {
        const accessToken = await auth.currentUser?.getIdToken(true);
        if (!accessToken) throw new Error("Missing cookie");
        dispatch(setAuthToken(accessToken));
        await tryLogin().unwrap(); // throw error if accessToken is expired
      } catch (error) {
        navigate("/login", {
          state: {
            from: location.pathname,
            search: location.search,
            message: "Please login to continue.",
          },
        });
      }
    };
    _checkToken();
  }, [dispatch, location, navigate, skip, tryLogin]);

  return (
    <>
      <Box flexGrow={1}>
        <AppBar />
      </Box>
      <Drawer />
      <Main open={system.drawerOpen}>
        <Box display="flex" flexDirection="row" flexGrow={1} justifyContent="center" m={1}>
          <Box display="flex" flexDirection="column" flexGrow={1} maxWidth={mainMaxWidth}>
            <ErrorBoundary FallbackComponent={AppFallback}>
              <OutletWithCheckedParams />
            </ErrorBoundary>
          </Box>
        </Box>
      </Main>
    </>
  );
}
