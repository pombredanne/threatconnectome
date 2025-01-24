import { Box, Button, Typography } from "@mui/material";
import PropTypes from "prop-types";
import React, { useState } from "react";

import { useApplyActionCodeMutation } from "../../services/firebaseApi";

export default function VerifyEmail(props) {
  const { oobCode } = props;
  const [disabled, setDisabled] = useState(false);
  const [message, setMessage] = useState(null);
  const [applyActionCode] = useApplyActionCodeMutation();

  function handleVerifyEmail() {
    setDisabled(true);
    applyActionCode({ actionCode: oobCode })
      .unwrap()
      .then((resp) => {
        setMessage("email verification success");
      })
      .catch((error) => {
        console.error(error);
        setMessage("something went wrong");
      });
  }

  return (
    <Box alignItems="center" display="flex" flexDirection="column">
      <Typography variant="h5" my={2}>
        Email Verification
      </Typography>
      <Button
        onClick={() => handleVerifyEmail()}
        disabled={disabled}
        variant="contained"
        sx={{
          textTransform: "none",
        }}
      >
        Verify Email
      </Button>
      <Box mt={3}>
        <Typography>{message}</Typography>
      </Box>
    </Box>
  );
}

VerifyEmail.propTypes = {
  oobCode: PropTypes.string,
};
