import { UploadFile } from "@mui/icons-material";
import { Tab, Tabs } from "@mui/material";
import { grey } from "@mui/material/colors";
import PropTypes from "prop-types";
import React, { useState } from "react";

export const StatusTabsAllServices = (props) => {
  const { setIsActiveUploadMode } = props;
  const [value, setValue] = useState(0);

  return (
    <Tabs value={value} onChange={(_, newValue) => setValue(newValue)}>
      <Tab
        label="All"
        onClick={() => setIsActiveUploadMode(0)}
        sx={{
          textTransform: "none",
          border: `1px solid ${grey[300]}`,
          borderRadius: "0.5rem 0.5rem 0 0",
          width: "10%",
          mt: 1,
        }}
      />
      <Tab
        icon={<UploadFile />}
        label="Upload"
        onClick={() => setIsActiveUploadMode(1)}
        sx={{
          textTransform: "none",
          border: `1px solid ${grey[300]}`,
          borderRadius: "0.5rem 0.5rem 0 0",
          width: "10%",
          mt: 1,
        }}
      />
    </Tabs>
  );
};

StatusTabsAllServices.propTypes = {
  setIsActiveUploadMode: PropTypes.func.isRequired,
};
