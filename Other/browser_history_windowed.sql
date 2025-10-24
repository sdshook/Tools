create table found as 

-- =====================================================================
-- COMPREHENSIVE USER ACTIVITY VIEW (VISITS + DOWNLOADS) AROUND TARGET(S)
-- Works on Chromium/Chrome/Edge History DBs.
-- Notes:
--   • Times are Chrome epoch (µs since 1601-01-01) → converted to localtime.
--   • Adjust BEFORE/AFTER window as needed.
--   • Optional filter in target_visits to focus on a URL pattern.
--   • Includes keyword_search_terms and visit_source if present.
--   • Downloads include final URL (if downloads_url_chains exists).
-- =====================================================================

WITH
-- ---------------------------------------------------------------------
-- Tunable window (in seconds)
-- BEFORE: window BEFORE target_time, AFTER: window AFTER
-- ---------------------------------------------------------------------
config AS (
  SELECT
    300  AS before_secs,   -- 5 minutes before
    600  AS after_secs     -- 10 minutes after
),

-- ---------------------------------------------------------------------
-- Pick target visits. OPTION A: restrict by URL pattern (recommended)
--   Uncomment/modify the WHERE clause to focus on A domain of interest.
-- OPTION B: remove WHERE to treat ALL VISITS as targets.
-- ---------------------------------------------------------------------
target_visits AS (
  SELECT v.id AS target_visit_id, v.visit_time AS target_time
  FROM visits v
  JOIN urls u ON u.id = v.url
  -- WHERE LOWER(u.url) LIKE LOWER('%uca.sa.com%')  -- <-- Optional focus
),

-- ---------------------------------------------------------------------
-- window around each target
-- ---------------------------------------------------------------------
windowed_visits AS (
  SELECT
    tv.target_visit_id,
    tv.target_time,
    (tv.target_time - (cfg.before_secs * 1000000)) AS start_time,
    (tv.target_time + (cfg.after_secs  * 1000000)) AS end_time
  FROM target_visits tv
  CROSS JOIN config cfg
),

-- ---------------------------------------------------------------------
-- Base VISITS context with referrer, transition, titles, search terms,
-- and visit source. (Some tables may be absent in older versions; if a
-- join errors, comment it out for your version.)
-- ---------------------------------------------------------------------
visits_context AS (
  SELECT
    w.target_visit_id,
    v.id                       AS visit_id,
    v.visit_time               AS event_time,
    NULL                       AS event_end_time,
    u.url                      AS url,
    u.title                    AS page_title,
    pv.id                      AS from_visit,
    ru.url                     AS referrer_url,
    v.visit_duration           AS visit_duration,         -- microseconds
    (v.transition & 255)       AS transition_code,
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
    END                        AS transition_label,
    kst.term                   AS search_term,            -- from omnibox if present
    vs.source                  AS visit_source_code       -- may be NULL if table missing
  FROM windowed_visits w
  JOIN visits v        ON v.visit_time BETWEEN w.start_time AND w.end_time
  JOIN urls   u        ON u.id = v.url
  LEFT JOIN visits pv  ON pv.id = v.from_visit
  LEFT JOIN urls   ru  ON ru.id = pv.url
  LEFT JOIN keyword_search_terms kst
                       ON kst.url_id = u.id              -- present on search result rows
  LEFT JOIN visit_source vs
                       ON vs.id = v.id                   -- visit_source may not exist on all builds
),

-- ---------------------------------------------------------------------
-- DOWNLOADS in the same window.
-- downloads_url_chains may not exist in all versions; if it does,
-- we take the *last* URL (final redirect) as final_url and optionally
-- the first URL as initial_url. If the table is missing, these will be NULL.
-- ---------------------------------------------------------------------
dl_chain_index AS (
  SELECT duc.id AS download_id,
         MAX(duc.chain_index) AS max_idx,
         MIN(duc.chain_index) AS min_idx
  FROM downloads_url_chains duc
  GROUP BY duc.id
),
dl_urls AS (
  SELECT
    duc.id                                      AS download_id,
    -- final URL (last in chain)
    MAX(CASE WHEN duc.chain_index = di.max_idx THEN duc.url END) AS final_url,
    -- initial/origin URL (first in chain)
    MAX(CASE WHEN duc.chain_index = di.min_idx THEN duc.url END) AS initial_url
  FROM downloads_url_chains duc
  JOIN dl_chain_index di ON di.download_id = duc.id
  GROUP BY duc.id
),
downloads_context AS (
  SELECT
    w.target_visit_id,
    d.id                    AS download_id,
    d.start_time            AS event_time,
    d.end_time              AS event_end_time,
    COALESCE(dl.final_url, d.tab_url)  AS url,           -- prefer final URL; fall back to tab_url
    d.tab_url               AS tab_url,
    d.target_path           AS target_path,
    d.current_path          AS current_path,
    d.mime_type             AS mime_type,
    d.opened                AS opened,
    d.danger_type           AS danger_type,
    d.interrupt_reason      AS interrupt_reason,
    dl.initial_url          AS initial_url
  FROM windowed_visits w
  JOIN downloads d
       ON ( (d.start_time BETWEEN w.start_time AND w.end_time)
         OR (d.end_time   BETWEEN w.start_time AND w.end_time) )
  LEFT JOIN dl_urls dl ON dl.download_id = d.id
),

-- ---------------------------------------------------------------------
-- Normalize to a single event stream (VISIT + DOWNLOAD)
-- ---------------------------------------------------------------------
events AS (
  -- VISITS
  SELECT
    vc.target_visit_id,
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

  -- DOWNLOADS
  SELECT
    dc.target_visit_id,
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

-- ---------------------------------------------------------------------
-- Final select with time conversion, relative position, and handy fields
-- ---------------------------------------------------------------------
SELECT
  e.target_visit_id,

  -- Target timestamp for reference (local time)
  datetime((tv.target_time/1000000) - 11644473600, 'unixepoch', 'localtime')
    AS target_local_time_pacific,

  -- Event timestamps (local time)
  datetime((e.event_time/1000000) - 11644473600, 'unixepoch', 'localtime')
    AS event_local_time_pacific,
  CASE
    WHEN e.event_time <  tv.target_time THEN 'BEFORE'
    WHEN e.event_time =  tv.target_time THEN 'AT_TARGET'
    ELSE 'AFTER'
  END AS relative_to_target,

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
JOIN target_visits tv ON tv.target_visit_id = e.target_visit_id
ORDER BY e.target_visit_id, e.event_time, e.event_type;
