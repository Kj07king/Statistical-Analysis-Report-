#library used in this project
library(jsonlite)

#cleaning know_exploited_vulnerabilities
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

# The code reads the NVD JSON file into a list and extract its main array of vulnerability records
raw_NVD <- fromJSON(file_path, simplifyVector = FALSE)
vulns_NVD <-raw_NVD$vulnerabilities

# the data in side vulnerability entry to filtered into its unique CVE ID and CVSS v3.1 metrics
extract_one <- function(entry){
  cve <- entry$cve
  cid <- cve$id
  metrics <- cve$metrics
  v31 <- metrics$cvssMetricV31
  
# The code extracts the primary CVSS v3.1 base score, defaulting to NA if metrics are missing
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
                    
# The code helps Convert the extracted list into a clean, structured data frame with typed columns for CVE IDs and scores
df <-data.frame(
  cveID = vapply(extracted, function(x) x$cveID, character(1)),
  cvss_score = vapply(extracted, function(x) ifelse(is.null(x$cvss_score),NA_real_,x$cvss_score),numeric(1)),
  stringsAsFacors = FALSE
)

#the code helps remove records by retaining only unique CVE IDs then return the finalized data frame
df <- df %>% distinct(cveID, .keep_all = TRUE)
return(df)
                 
# Load NVD feeds
nvd_2024 <- parse_nvd_feed("nvdcve-2.0-2024.json")
nvd_2025 <- parse_nvd_feed("nvdcve-2.0-2025.json")
nvd_2026 <- parse_nvd_feed("nvdcve-2.0-2026.json")

# combining the NVD feeds and remove deuplicates form NVD records
nvd_combined <- bind_rows(nvd_2024, nvd_2025, nvd_2026) %>%
  distinct(cveID, .keep_all = TRUE) 
