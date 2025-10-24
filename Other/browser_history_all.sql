-- Chrome / Edge Browser History Compilation 
-- (c) Shane D Shook, 2025
CREATE TABLE foundall AS

WITH

-- VISITS context for all visits
visits_context AS (
  SELECT
    v.id                 AS visit_id,
    v.visit_time         AS event_time,
    NULL                 AS event_end_time,
    u.url                AS url,
    u.title              AS page_title,
    pv.id                AS from_visit,
    ru.url               AS referrer_url,
    v.visit_duration     AS visit_duration,
    (v.transition & 255) AS transition_code,
    CASE (v.transition & 255)
      WHEN 0  THEN 'LINK'
      WHEN 1  THEN 'TYPED'
      WHEN 2  THEN 'AUTO_BOOKMARK'
      WHEN 3  THEN 'AUTO_SUBFRAME'
      WHEN 4  THEN 'MANUAL_SUBFRAME'
      WHEN 5  THEN 'GENERATED'
      WHEN 6  THEN 'START_PAGE'
      WHEN 7  THEN 'FORM_SUBMIT'
      WHEN 8  THEN 'RELOAD'
      WHEN 9  THEN 'KEYWORD'
      WHEN 10 THEN 'KEYWORD_GENERATED'
      ELSE 'OTHER'
    END                 AS transition_label,
    kst.term            AS search_term,
    vs.source           AS visit_source_code
  FROM visits v
  JOIN urls u           ON u.id = v.url
  LEFT JOIN visits pv   ON pv.id = v.from_visit
  LEFT JOIN urls ru     ON ru.id = pv.url
  LEFT JOIN keyword_search_terms kst
                        ON kst.url_id = u.id
  LEFT JOIN visit_source vs
                        ON vs.id = v.id
),

-- DOWNLOAD URL chain index (if downloads_url_chains exists)
dl_chain_index AS (
  SELECT
    duc.id               AS download_id,
    MAX(duc.chain_index) AS max_idx,
    MIN(duc.chain_index) AS min_idx
  FROM downloads_url_chains duc
  GROUP BY duc.id
),

-- Resolve initial/final download URLs
dl_urls AS (
  SELECT
    duc.id AS download_id,
    MAX(CASE WHEN duc.chain_index = di.max_idx THEN duc.url END) AS final_url,
    MAX(CASE WHEN duc.chain_index = di.min_idx THEN duc.url END) AS initial_url
  FROM downloads_url_chains duc
  JOIN dl_chain_index di ON di.download_id = duc.id
  GROUP BY duc.id
),

-- All downloads
downloads_context AS (
  SELECT
    d.id                    AS download_id,
    d.start_time            AS event_time,
    d.end_time              AS event_end_time,
    COALESCE(dl.final_url, d.tab_url) AS url,
    d.tab_url               AS tab_url,
    d.target_path           AS target_path,
    d.current_path          AS current_path,
    d.mime_type             AS mime_type,
    d.opened                AS opened,
    d.danger_type           AS danger_type,
    d.interrupt_reason      AS interrupt_reason,
    dl.initial_url          AS initial_url
  FROM downloads d
  LEFT JOIN dl_urls dl ON dl.download_id = d.id
),

-- Unified event stream: visits + downloads
events AS (
  SELECT
    'VISIT'                        AS event_type,
    vc.visit_id                    AS id_in_type,
    vc.event_time,
    vc.event_end_time,
    vc.url,
    vc.page_title,
    vc.referrer_url,
    vc.transition_code,
    vc.transition_label,
    vc.search_term,
    vc.visit_source_code,
    NULL                           AS target_path,
    NULL                           AS current_path,
    NULL                           AS mime_type,
    NULL                           AS opened,
    NULL                           AS danger_type,
    NULL                           AS interrupt_reason,
    NULL                           AS initial_url
  FROM visits_context vc

  UNION ALL

  SELECT
    'DOWNLOAD'                     AS event_type,
    dc.download_id                 AS id_in_type,
    dc.event_time,
    dc.event_end_time,
    dc.url,
    NULL                           AS page_title,
    dc.tab_url                     AS referrer_url,
    NULL                           AS transition_code,
    'DOWNLOAD'                     AS transition_label,
    NULL                           AS search_term,
    NULL                           AS visit_source_code,
    dc.target_path,
    dc.current_path,
    dc.mime_type,
    dc.opened,
    dc.danger_type,
    dc.interrupt_reason,
    dc.initial_url
  FROM downloads_context dc
)

-- Final output select
SELECT
  datetime((e.event_time/1000000) - 11644473600, 'unixepoch', 'localtime')
    AS event_local_time_pacific,
  e.event_type,
  e.id_in_type,
  e.url,
  e.page_title,
  e.referrer_url,
  e.transition_code,
  e.transition_label,
  e.search_term,
  e.visit_source_code,
  e.target_path,
  e.current_path,
  e.mime_type,
  e.opened,
  e.danger_type,
  e.interrupt_reason,
  e.initial_url
FROM events e
ORDER BY e.event_time, e.event_type

;
