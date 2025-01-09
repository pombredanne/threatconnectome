import { Box, Checkbox } from "@mui/material";
import PropTypes from "prop-types";
import React from "react";

export function AuthAdminCheckbox(props) {
  const { checked, editable, modified, onChange } = props;

  return (
    <>
      <Box display="flex" flexDirection="row" alignItems="center" width="40px">
        <Checkbox
          checked={checked}
          disabled={!editable}
          onChange={editable ? onChange : undefined}
          fontSize="small"
        />
        {modified && "*"}
      </Box>
    </>
  );
}

AuthAdminCheckbox.propTypes = {
  checked: PropTypes.bool.isRequired,
  editable: PropTypes.bool.isRequired,
  modified: PropTypes.bool.isRequired,
  onChange: PropTypes.func.isRequired,
};
