import { Update as UpdateIcon } from "@mui/icons-material";
import {
  Box,
  Button,
  Card,
  CardActions,
  CardContent,
  Chip,
  Collapse,
  Divider,
  List,
  Switch,
  Typography,
} from "@mui/material";
import { grey } from "@mui/material/colors";
import PropTypes from "prop-types";
import React, { useState } from "react";
import { useParams } from "react-router-dom";

import { UUIDTypography } from "../../components/UUIDTypography";
import { useSkipUntilAuthTokenIsReady } from "../../hooks/auth";
import {
  useGetPTeamTopicActionsQuery,
  useGetTicketsQuery,
  useGetTagsQuery,
  useGetTopicQuery,
  useGetDependenciesQuery,
} from "../../services/tcApi";
import { APIError } from "../../utils/APIError";
import { dateTimeFormat, errorToString } from "../../utils/func";
import { parseVulnerableVersions, versionMatch } from "../../utils/versions";

import { ActionItem } from "./ActionItem";
import { TopicTicketAccordion } from "./TopicTicketAccordion";

export function TopicCard(props) {
  const { pteamId, topicId, service, references, members } = props;
  const { tagId } = useParams();
  const serviceId = service?.service_id;

  const [detailOpen, setDetailOpen] = useState(false);
  const [actionFilter, setActionFilter] = useState(true);
  const skipByAuth = useSkipUntilAuthTokenIsReady();

  const {
    data: topic,
    error: topicError,
    isLoading: topicIsLoading,
  } = useGetTopicQuery(topicId, { skipByAuth });

  const skipByPTeamId = pteamId === undefined;
  const skipByTopicId = topicId === undefined;
  const skipByServiceId = serviceId === undefined;
  const skipBytagId = tagId === undefined;
  const getDependenciesReady = !skipByAuth && pteamId && serviceId;

  const {
    data: serviceDependencies,
    error: serviceDependenciesError,
    isLoading: serviceDependenciesIsLoading,
  } = useGetDependenciesQuery({ pteamId, serviceId }, { skip: !getDependenciesReady });
  const {
    data: allTags,
    error: allTagsError,
    isLoading: allTagsIsLoading,
  } = useGetTagsQuery(undefined, { skipByAuth });
  const {
    data: pteamTopicActionsData,
    error: pteamTopicActionsError,
    isLoading: pteamTopicActionsIsLoading,
  } = useGetPTeamTopicActionsQuery(
    { topicId, pteamId },
    { skip: skipByAuth || skipByPTeamId || skipByTopicId },
  );

  const {
    data: tickets,
    error: ticketsRelatedToServiceTopicTagError,
    isLoading: ticketsRelatedToServiceTopicTagIsLoading,
  } = useGetTicketsQuery(
    { pteamId, serviceId, topicId, tagId },
    { skip: skipByAuth || skipByPTeamId || skipByTopicId || skipByServiceId || skipBytagId },
  );

  const handleDetailOpen = () => setDetailOpen(!detailOpen);

  if (skipByAuth || skipByPTeamId || skipByTopicId || skipByServiceId || skipBytagId) return <></>;
  if (pteamTopicActionsError)
    throw new APIError(errorToString(pteamTopicActionsError), { api: "getPTeamTopicActions" });
  if (pteamTopicActionsIsLoading) return <>Now loading topicActions...</>;
  if (ticketsRelatedToServiceTopicTagError)
    throw new APIError(errorToString(ticketsRelatedToServiceTopicTagError), {
      api: "getTicketsRelatedToServiceTopicTag",
    });
  if (ticketsRelatedToServiceTopicTagIsLoading) return <>Now loading tickets...</>;
  if (topicError) throw new APIError(errorToString(topicError), { api: "getTopic" });
  if (topicIsLoading) return <>Now loading Topic...</>;
  if (allTagsError) throw new APIError(errorToString(allTagsError), { api: "getAllTags" });
  if (allTagsIsLoading) return <>Now loading allTags...</>;
  if (serviceDependenciesError)
    throw new APIError(errorToString(serviceDependenciesError), { api: "getServiceDependencies" });
  if (serviceDependenciesIsLoading) return <>Now loading serviceDependencies...</>;
  if (!pteamId || !serviceId || !members || !tagId) {
    return <>Now Loading...</>;
  }

  const pteamTopicActions = pteamTopicActionsData.actions;

  const isSolved = !tickets.find((ticket) => ticket.ticket_status?.topic_status !== "completed");
  const currentTagDict = allTags.find((tag) => tag.tag_id === tagId);

  const takenActionLogs = isSolved // FIXME: WORKAROUND, just list taken actions of each tickets
    ? tickets.reduce((ret, ticket) => [...ret, ...ticket.ticket_status.action_logs], [])
    : [];

  // oops, ext.tags are list of tag NAME. (because generated by script without TC)
  const isRelatedAction = (action, tagName) =>
    (!action.ext?.tags?.length > 0 || action.ext.tags.includes(tagName)) &&
    (!action.ext?.vulnerable_versions?.[tagName]?.length > 0 ||
      parseVulnerableVersions(action.ext.vulnerable_versions[tagName]).some(
        (actionVersion) =>
          !references?.length > 0 ||
          references?.some((ref) =>
            versionMatch(
              ref.version,
              actionVersion.ge,
              actionVersion.gt,
              actionVersion.le,
              actionVersion.lt,
              actionVersion.eq,
              true,
            ),
          ),
      ));
  const topicActions = actionFilter
    ? pteamTopicActions?.filter(
        (action) =>
          isRelatedAction(action, currentTagDict.tag_name) ||
          isRelatedAction(action, currentTagDict.parent_name),
      )
    : (pteamTopicActions ?? []);

  return (
    <Card variant="outlined" sx={{ marginTop: "8px", marginBottom: "20px", width: "100%" }}>
      <Box
        display="flex"
        flexDirection="row"
        justifyContent="space-between"
        alignItems="flex-start"
      >
        <Box display="flex" flexDirection="row" alignItems="flex-start" m={2} mb={1}>
          <Box display="flex" flexDirection="column" mr={1}>
            <Typography variant="h5" fontWeight={900}>
              {topic.title}
            </Typography>
            <UUIDTypography>{topic.topic_id}</UUIDTypography>
            <Box alignItems="center" display="flex" flexDirection="row" sx={{ color: grey[600] }}>
              <UpdateIcon fontSize="small" />
              <Typography ml={0.5} variant="caption">
                {dateTimeFormat(topic.updated_at)}
              </Typography>
            </Box>
          </Box>
        </Box>
      </Box>
      <Divider />
      <Box display="flex" sx={{ height: "350px" }}>
        <Box
          flexGrow={1}
          display="flex"
          flexDirection="column"
          justifyContent="space-between"
          sx={{ overflowY: "auto" }}
        >
          <CardContent>
            {!isSolved ? (
              topicActions && (
                <>
                  <Box alignItems="center" display="flex" flexDirection="row" mb={1}>
                    <Typography mr={2} sx={{ fontWeight: 900 }}>
                      Recommended action
                      {topicActions.filter((action) => action.recommended).length > 1 ? "s" : ""}
                    </Typography>
                    <Chip
                      size="small"
                      label={topicActions.filter((action) => action.recommended).length}
                      sx={{ backgroundColor: grey[300], fontWeight: 900 }}
                    />
                    <Box display="flex" flexGrow={1} flexDirection="row" />
                    <Switch
                      checked={actionFilter}
                      onChange={() => setActionFilter(!actionFilter)}
                      size="small"
                      color="success"
                    />
                    <Typography>Action filter</Typography>
                  </Box>
                  <List
                    sx={{
                      width: "100%",
                      position: "relative",
                      overflow: "auto",
                      maxHeight: 200,
                    }}
                  >
                    {topicActions
                      .filter((action) => action.recommended)
                      .map((action) => (
                        <ActionItem
                          key={action.action_id}
                          action={action.action}
                          actionId={action.action_id}
                          actionType={action.action_type}
                          createdAt={action.created_at}
                          recommended={action.recommended}
                          ext={action.ext}
                          focusTags={
                            actionFilter
                              ? null
                              : [currentTagDict.tag_name, currentTagDict.parent_name]
                          }
                        />
                      ))}
                  </List>
                </>
              )
            ) : (
              <>
                <Box alignItems="center" display="flex" flexDirection="row" mb={2}>
                  <Typography mr={2} sx={{ fontWeight: 900 }}>
                    Taken Action
                    {takenActionLogs.length > 1 ? "s" : ""}
                  </Typography>
                  <Chip
                    size="small"
                    label={takenActionLogs.length}
                    sx={{ backgroundColor: grey[300], fontWeight: 900 }}
                  />
                  <Box display="flex" flexGrow={1} flexDirection="row" />
                  <Switch
                    checked={actionFilter}
                    onChange={() => setActionFilter(!actionFilter)}
                    size="small"
                  />
                  <Typography>Action filter</Typography>
                </Box>
                <List
                  sx={{
                    width: "100%",
                    position: "relative",
                    overflow: "auto",
                    maxHeight: 200,
                  }}
                >
                  {takenActionLogs.map((log) => (
                    <ActionItem
                      key={log.logging_id}
                      action={log.action}
                      actionId={log.action_id}
                      actionType={log.action_type}
                      recommended={log.recommended}
                    />
                  ))}
                </List>
              </>
            )}
            <Collapse in={detailOpen}>
              {(() => {
                const otherActions = topicActions?.filter((action) =>
                  isSolved
                    ? !takenActionLogs?.find((log) => log.action_id === action.action_id)
                    : !action.recommended,
                );
                return otherActions?.length >= 1 ? (
                  <>
                    <Box alignItems="baseline" display="flex" flexDirection="columns" mt={4}>
                      <Typography mr={2} sx={{ fontWeight: 900 }}>
                        Other action{otherActions.length > 1 ? "s" : ""}
                      </Typography>
                      <Chip
                        size="small"
                        label={otherActions.length}
                        sx={{ backgroundColor: grey[300], fontWeight: 900 }}
                      />
                    </Box>
                    <List
                      sx={{
                        width: "100%",
                        position: "relative",
                        overflow: "auto",
                        maxHeight: 200,
                      }}
                    >
                      {otherActions.map((action) => (
                        <ActionItem
                          key={action.action_id}
                          action={action.action}
                          actionId={action.action_id}
                          actionType={action.action_type}
                          createdAt={action.created_at}
                          recommended={action.recommended}
                          ext={action.ext}
                          focusTags={
                            actionFilter
                              ? null
                              : [currentTagDict.tag_name, currentTagDict.parent_name]
                          }
                        />
                      ))}
                    </List>
                  </>
                ) : (
                  <></>
                );
              })()}
              {topic.misp_tags && topic.misp_tags.length > 0 && (
                <>
                  <Typography sx={{ fontWeight: 900 }} mt={3} mb={2}>
                    Topic tags
                  </Typography>
                  <Box mb={5}>
                    {topic.misp_tags.map((mispTag) => (
                      <Chip
                        key={mispTag.tag_id}
                        label={mispTag.tag_name}
                        sx={{ mr: 1, borderRadius: "3px" }}
                        size="small"
                      />
                    ))}
                  </Box>
                </>
              )}
              {topic.abstract && (
                <>
                  <Typography sx={{ fontWeight: 900 }} mb={2}>
                    Detail
                  </Typography>
                  <Typography variant="body">{topic.abstract}</Typography>
                </>
              )}
            </Collapse>
          </CardContent>
          <CardActions sx={{ display: "flex", justifyContent: "flex-end", mb: 1 }}>
            <Button
              color="primary"
              onClick={handleDetailOpen}
              size="small"
              sx={{ marginRight: "auto", textTransform: "none" }}
            >
              {detailOpen ? "Hide" : "Show"} Details
            </Button>
          </CardActions>
        </Box>
        <Divider flexItem={true} orientation="vertical" />
        <Box
          sx={{
            overflowY: "auto",
            minWidth: "480px",
            maxWidth: "480px",
          }}
        >
          {tickets.map((ticket, index) => (
            <TopicTicketAccordion
              key={ticket.ticket_id}
              pteamId={pteamId}
              dependency={serviceDependencies.find(
                (dependency) => dependency.dependency_id === ticket.threat.dependency_id,
              )}
              topicId={topicId}
              ticket={ticket}
              serviceSafetyImpact={service.service_safety_impact}
              members={members}
              defaultExpanded={index === 0}
              topicActions={topicActions}
            />
          ))}
        </Box>
      </Box>
    </Card>
  );
}

TopicCard.propTypes = {
  pteamId: PropTypes.string.isRequired,
  topicId: PropTypes.string.isRequired,
  service: PropTypes.object.isRequired,
  references: PropTypes.array.isRequired,
  members: PropTypes.object.isRequired,
};
