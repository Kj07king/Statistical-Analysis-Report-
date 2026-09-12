
#cleaning know_exploited_vulnerabilities
cleaned_KEV_df <- read.csv("know_exploited_vulberabilities.csv" , stringsAsFactors = False) %>%
  mutate(
    dateAdded = as.Data(dateAdded),
    dueDate = as.Data(dueDate),
    Remediation_Days = as.numeric(difftime(dueDate, dateAdded, units = "days"))
  ) %>%
filter(Remediation_day >= 0) %>%
select(cveID, dateAdded, dueDate, Remediation_Days)


