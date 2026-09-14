#library used in this project
library(jsonlite)

# we clean know_exploited_vulnerabilities
cleaned_KEV_df <- read.csv("know_exploited_vulberabilities.csv" , stringsAsFactors = False) %>%
  mutate(
    dateAdded = as.Data(dateAdded),
    dueDate = as.Data(dueDate),
    Remediation_Days = as.numeric(difftime(dueDate, dateAdded, units = "days"))
  ) %>%
filter(Remediation_day >= 0) %>%
distinct(cveID, .keep_all = TRUE)
select(cveID, dateAdded, dueDate, Remediation_Days)

#Breaking down NVD json Feeds (2024-2026)

# The code checks for JSON file existence to prevent runtime crashes and returning an empty typed data frame if missing
parse_nvd_feed <- function(file_path) {
  if (!file.exists(file_path)) {
    warning("File not found: ", file_path)
    return(data.frame(cveID = character(), cvss_score = numeric(), stringsAsFactors = FALSE))
  }

# The code reads the NVD JSON file into a list and extract its main array of vulnerability records
raw_NVD <- fromJSON(file_path, simplifyVector = FALSE)
vulns_NVD <-raw_NVD$vulnerabilities

# the data in side vulnerability entry to filtered into its unique CVE ID and CVSS v3.1 metrics
extract_one <- function(entry){
  cve <- entry$cve
  cid <- cve$id
  metrics <- cve$metrics
  v31 <- metrics$cvssMetricV31
  
# The code extracts the primary CVSS v3.1 base score and defaulting to NA if metrics are missing
  score <- NA_real_
  if(!is.null(v31) && length(v31) > 0) {
    types <- sapply(v31, function(m) m$type)
    primary_idx <- which(types == "Primary")
    chosen <- if (length(primary_idx) > 0) v31[[primary_idx[1]]] else v31 [[1]]
    score <- chosen$cvssData$baseScore
  }
# The code returns the extracted CVE ID and CVSS score as a key-value list to complete the inner function
  list(cveId = cid, cvss_score = score)
}
# the code repeat all vulnerability entries using extract_one to build a list of extracted IDs and scores
extracted <-lapply(vulns_NVD, extract_one)
                    
# The code helps Convert the extracted list into a clean and  structured data frame with typed columns for CVE IDs and scores
df <-data.frame(
  cveID = vapply(extracted, function(x) x$cveID, character(1)),
  cvss_score = vapply(extracted, function(x) ifelse(is.null(x$cvss_score),NA_real_,x$cvss_score),numeric(1)),
  stringsAsFacors = FALSE
)

#the code helps remove records by retaining only unique CVE IDs then return the finalized data frame
df <- df %>% distinct(cveID, .keep_all = TRUE)
return(df)
                 
# the code helps load NVD feeds
nvd_2024 <- parse_nvd_feed("nvdcve-2.0-2024.json")
nvd_2025 <- parse_nvd_feed("nvdcve-2.0-2025.json")
nvd_2026 <- parse_nvd_feed("nvdcve-2.0-2026.json")

# The code combins the NVD feeds and remove deuplicates form NVD records
nvd_combined <- bind_rows(nvd_2024, nvd_2025, nvd_2026) %>%
  distinct(cveID, .keep_all = TRUE) 

# The code helps print console logs summarizing total imported NVD records by year and missing CVSS score counts
cat("Data Quality Assessment:\n")
cat("  - 2024 Records:", nrow(nvd_2024), "\n")
cat("  - 2025 Records:", nrow(nvd_2025), "\n")
cat("  - 2026 Records:", nrow(nvd_2026), "\n")
cat("  - Total Records:", nrow(nvd_combined), "\n")
cat("  - Records with no CVSS v3.1 score (NA):", sum(is.na(nvd_combined$cvss_score)), "\n\n)

#Data Merging & Cleaning

# The code merges CISA KEV and NVD datasets by CVE ID to a new dataset analysis_df and then filters out missing CVSS scores record and remediation days
analysis_df <- inner_join(kev_def, nvd_combined, by = "cveID") %>%
  filter(!is.na(cvss_score), !is.na(Remediation_day))

# we divided the code into categorize CVSS scores into standard qualitative severity tiers based on NVD base score thresholds for the One-way Anova test
analysis_df <- analysis_df %>%
  mutate(
    severity = case_when(
      cvss_score >= 9.0 ~"Critical",
      cvss_score >= 7.0 ~"High",
      cvss_score >= 4.0 ~"Medium",
      TRUE ~"Low"
    ),
# The code converts severity to an ordered factor ensuring proper sequence for statistical models and plots
    severity = factor(severity, levels = c("Low","Medium","High","Critical"))
  )

# I have included this code as it helps log data quality diagnostics which helps verify final sample size and  total missing scores and zero residual duplicates
cat("Data Quality Assessment:\n")
cat(" - Final Analysis Records:," nrow(analysis_df),"\n")
cat(" - Missing CVSS Scores in NVD:," sum(is.na(nvd_combined$cvss_score)),"\n")
cat(" - Dupliacte CVE IDs in final Data:", n_distinct(analysis_df$cveID) - nrow(analysis_df),"\n\n")

# To output the frequency counts of vulnerabilities across each CVSS severity tier to check if there is balance between categories 
cat("Severity distribution:\n")
print(table(analysis_df$severity))

