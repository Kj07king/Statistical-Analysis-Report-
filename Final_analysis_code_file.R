#library used in this project:
library(jsonlite)
library(dplyr)
library(lubridate)
library(ggplot2)
library(effectsize)
library(car)           
library(lmtest) 
library(pwr)           
library(rstatix)    

# we clean know_exploited_vulnerabilities
cleaned_KEV_df <- read.csv("known_exploited_vulnerabilities.csv" , stringsAsFactors = FALSE) %>%
  mutate(
    dateAdded = as.Date(dateAdded),
    dueDate = as.Date(dueDate),
    Remediation_Days = as.numeric(difftime(dueDate, dateAdded, units = "days"))
  ) %>%
filter(Remediation_Days >= 0) %>%
 distinct(cveID, .keep_all = TRUE) %>%   
 select(cveID, dateAdded, dueDate, Remediation_Days)

# the code shows that the CSV file is loaded and prints the total recodrs and data range in it. 
cat("CISA KEV Data Loaded:\n")
cat("  - Total Records:", nrow(cleaned_KEV_df), "\n")
cat("  - Date Range:", as.character(min(cleaned_KEV_df$dateAdded)), "to", as.character(max(cleaned_KEV_df$dateAdded)), "\n\n")

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
    metrics <- cve$metrics
    v31 <- metrics$cvssMetricV31
  
# The code extracts the primary CVSS v3.1 base score and defaulting to NA if metrics are missing
    score <- NA_real_
    if (!is.null(v31) && length(v31) > 0) {
      types <- sapply(v31, function(m) m$type)
      primary_idx <- which(types == "Primary")
      chosen <- if (length(primary_idx) > 0) v31[[primary_idx[1]]] else v31 [[1]]
      score <- chosen$cvssData$baseScore
    }
# The code returns the extracted CVE ID and CVSS score as a key-value list to complete the inner function
  list(cveId = cve$id, cvss_score = score)
}
# the code repeat all vulnerability entries using extract_one to build a list of extracted IDs and scores
  extracted <-lapply(vulns_NVD, extract_one)
                    
# The code helps Convert the extracted list into a clean and  structured data frame with typed columns for CVE IDs and scores
df <-data.frame(
  cveID = vapply(extracted, function(x) x$cveID, character(1)),
  cvss_score = vapply(extracted, function(x) ifelse(is.null(x$cvss_score), NA_real_, x$cvss_score), numeric(1)),
  stringsAsFactors = FALSE
)

#the code helps remove records by retaining only unique CVE IDs then return the finalized data frame
df <- df %>% distinct(cveID, .keep_all = TRUE)
return(df)
}               
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
cat("  - Records with no CVSS v3.1 score (NA):", sum(is.na(nvd_combined$cvss_score)), "\n\n")

#Data Merging & Cleaning

# The code merges CISA KEV and NVD datasets by CVE ID to a new dataset analysis_df and then filters out missing CVSS scores record and remediation days
analysis_df <- inner_join(cleaned_KEV_df , nvd_combined, by = "cveID") %>%
  filter(!is.na(cvss_score), !is.na(Remediation_Days))

# we divided the code into categorize CVSS scores into standard qualitative Severity tiers based on NVD base score thresholds for the One-way Anova test
analysis_df <- analysis_df %>%
  mutate(
    Severity = case_when(
      cvss_score >= 9.0 ~"Critical",
      cvss_score >= 7.0 ~"High",
      cvss_score >= 4.0 ~"Medium",
      TRUE ~"Low"
    ),
# The code converts Severity to an ordered factor ensuring proper sequence for statistical models and plots
    Severity = factor(Severity, levels = c("Low","Medium","High","Critical"))
  )

# I have included this code as it helps log data quality diagnostics which helps verify final sample size and  total missing scores and zero residual duplicates
cat("Data Quality Assessment:\n")
cat("  - Final Analysis Records:", nrow(analysis_df), "\n")
cat("  - Missing CVSS Scores in NVD:", sum(is.na(nvd_combined$cvss_score)), "\n")
cat("  - Duplicate CVE IDs in Final Data:", n_distinct(analysis_df$cveID) - nrow(analysis_df), "\n\n")

# To output the frequency counts of vulnerabilities across each CVSS Severity tier to check if there is balance between categories 
cat("Severity distribution:\n")
print(table(analysis_df$Severity))

#Visualiztions:
# the code there is used to create a Scattor plot 
scatter_plot <- ggplot(analysis_df, aes(x = cvss_score, y = Remediation_Days)) +
  geom_point(alpha = 0.4, color = "pink") +
  geom_smooth(method = "lm", color = "yellow", se = TRUE) +
  theme_minimal() +
  labs(
    title = "CVSS Score vs. CISA Remediation Days (2024-2026)" ,
    x = "CVSS v3.1 Base score",
    y = "Mandated Remediation Window (Days)"
  ) +
  theme(plot.title = element_text(hjust = 0.5, face = "bold"), axis.title = element_text(face = "bold"))

# prints the scatter_plot code above and saves a png file of it in the users file path and notifises the user about it through the console  
print(scatter_plot)
ggsave("scatter_cvss_vs_remediation.png", scatter_plot, width = 8, height = 6, dpi = 300)
cat("Scatterplot saved to: scatter_cvss_vs_remediation.png\n")

# the code there is used to create a box plot 
box_plot<- ggplot(analysis_df, aes(x = Severity, y = Remediation_Days, fill = Severity)) +
  geom_boxplot(alpha = 0.7) +
  geom_jitter(width = 0.2, alpha = 0.3, size = 1) +
  theme_minimal() +
  labs(
    title = "Remediation Window by CVSS Severity Tier (2024-2026)",
    x = "CVSS v3.1 Severity Tier",
    y = "Mandated Remediation Window (Days)"
  ) +
  theme(plot.title = element_text(hjust = 0.5, face = "bold"), axis.title = element_text(face = "bold"), legend.position = "none") +
  scale_fill_manual(values = c("Low" = "green", "Medium" = "purple", "High" = "orange", "Critical" = "gold"))

# prints the box_plot code above and saves a png file of it in the users file path and notifises the user about it through the console                   
print(box_plot)
ggsave("boxplot_Severity_vs_remediation.png", box_plot, width = 8, height = 6, dpi = 300)
cat("Boxplot saved to: boxplot_Severity_vs_remediation.png\n\n")

# Descriptive Statistics
                 
# we calculate the summary statistics for remediation days grouped by CVSS Severity tier
Descr_stats <- analysis_df %>%
  group_by(Severity) %>%
  summarise(
    Count = n(),
    mean_Days = round(mean(Remediation_Days), 3),
    median_Days = median(Remediation_Days),
    sd_Days = round(sd(Remediation_Days), 3),
    IQR_Days = IQR(Remediation_Days),
    min_Days = min(Remediation_Days),
    max_Days = max(Remediation_Days)
  )

# prints the descriptive statics for remediation days written above in the code                   
cat("Descriptive Statistics by Severity Tier:\n")
print(Descr_stats)
cat("\n")

# prints the Cvss scroe mean,sd and remediation day mean,sd,median, and range and rounds some of the values to 3 decimal places 
cat("Overall Summary Statistics:\n")
cat("  - CVSS score mean:", round(mean(analysis_df$cvss_score), 3), "\n")
cat("  - CVSS score sd:", round(sd(analysis_df$cvss_score), 3), "\n")
cat("  - Remediation days mean:", round(mean(analysis_df$Remediation_Days), 3), "\n")
cat("  - Remediation days sd:", round(sd(analysis_df$Remediation_Days), 3), "\n")
cat("  - Remediation days median:", median(analysis_df$Remediation_Days), "\n")
cat("  - Remediation days range:", min(analysis_df$Remediation_Days), "to", max(analysis_df$Remediation_Days), "\n\n")

# Infernetial statistics: Model Application for linear regression and one-way anova 

# the code fits an linear regression model testing CVSS base score as a predictor of remediation duration
lm_fit <- lm(Remediation_Days ~ cvss_score, data = analysis_df)

# Prints linear regression summary the console and it self                 
cat("Liner Regression Summary:\n")
linear_reg_summary <- summary(lm_fit)
print(linear_reg_summary)
cat("\n")
                 
# the code calculates and prints 95% confidence intervals for the regression coefficients
cat("95% Confidence Intervals for Coefficients:\n")
conf_intervals <- confint(lm_fit, level = 0.95)
print(conf_intervals)
cat("\n")
                 
# the code outputs information criteria  AIC , BIC and residual standard error to evaluate model fit
cat("Model Fit Metrics:\n")
cat("  - AIC:", round(AIC(lm_fit), 2), "\n")
cat("  - BIC:", round(BIC(lm_fit), 2), "\n")
cat("  - Residual Standard Error:", round(summary(lm_fit)$sigma, 3), "\n\n")

# One-way Anova: 
                 
# I print the ANOVA section header and research question framing mean remediation differences across Severity tiers on the console                 
cat("MODEL 2: ONE-WAY ANOVA \n")
cat("Research Question: Do Severity tiers differ in mean remediation days?\n\n")
                 
# the code fits the one-way ANOVA model evaluating differences in mean remediation time across qualitative Severity tiers
anova_fit <- aov(Remediation_Days ~ Severity, data = analysis_df)
                 
# I print the overall ANOVA table including F-statistic and p-value
cat("One-way ANOVA Summary:\n")
anova_summary <- summary(anova_fit)
print(anova_summary)
cat("\n")
                 
# ETA-squared:
# I Calculate Eta-Squared effect size with 95% confidence intervals to quantify the variance explained by Severity tiers                
cat("EFFECT SIZE Squared \n")
eta <- eta_squared(anova_fit, ci = 0.95)
print(eta)
cat("\n")

#Assumption validatiors 

# I evaluate residual normality using Shapiro-Wilk test with CLT context for large samples                 
cat("--- NORMALITY OF RESIDUALS ---\n")

shapiro_reg <- shapiro.test(residuals(lm_fit))
cat("Shapiro-Wilk Test (Regression Residuals):\n")
cat("  - W-statistic:", round(shapiro_reg$statistic, 4), "\n")
cat("  - p-value:", round(shapiro_reg$p.value, 4), "\n")
cat("  - Interpretation:", ifelse(shapiro_reg$p.value < 0.05, 
    "Violated (p < 0.05) - but robust due to CLT (N > 30 per group)", 
    "Satisfied (p >= 0.05)"), "\n\n")

# I assess the homoscedasticity of linear model residuals using the Breusch-Pagan test
cat("--- HOMOSCEDASTICITY ---\n")

bp_test <- bptest(lm_fit)
cat("Breusch-Pagan Test (Regression):\n")
cat("  - BP-statistic:", round(bp_test$statistic, 4), "\n")
cat("  - p-value:", round(bp_test$p.value, 4), "\n")
cat("  - Interpretation:", ifelse(bp_test$p.value < 0.05, 
    "Violated (p < 0.05) - heteroscedasticity present", 
    "Satisfied (p >= 0.05) - homoscedasticity confirmed"), "\n\n")

# the code performs Levene's test to evaluate homogeneity of variance across ANOVA Severity groups
cat("--- LEVENE'S TEST ---\n")

levene_test <- leveneTest(Remediation_Days ~ Severity, data = analysis_df)
cat("Levene's Test (ANOVA - Homogeneity of Variance):\n")
cat("  - F-statistic:", round(levene_test$`F value`[1], 4), "\n")
cat("  - p-value:", round(levene_test$`Pr(>F)`[1], 4), "\n")
cat("  - Interpretation:", ifelse(levene_test$`Pr(>F)`[1] < 0.05, 
    "Violated (p < 0.05) - unequal variances", 
    "Satisfied (p >= 0.05) - equal variances confirmed"), "\n\n")


# code for dignoticst plots 

# the code helps generate and export 2x2 diagnostic plots (Residuals vs Fitted, Q-Q, Scale-Location, Residuals vs Leverage) for OLS regression evaluation                 
png("diagnostic_plots_regression.png", width = 12, height = 10, units = "in", res = 300)
par(mfrow = c(2, 2))
plot(lm_fit)
dev.off()
cat("Regression diagnostic plots saved to: diagnostic_plots_regression.png\n")
                 
# the code export ANOVA diagnostic plots assessing homoscedasticity and residual normality across Severity tiers
png("diagnostic_plots_anova.png", width = 12, height = 6, units = "in", res = 300)
par(mfrow = c(1, 2))
plot(anova_fit, which = 1:2)
dev.off()
cat("ANOVA diagnostic plots saved to: diagnostic_plots_anova.png\n\n")


# the code give us the modle statistics summary

# The code shows the  regression performance metrics including R-squared, overall model significance, and slope confidence intervals
cat("  - R-squared:", round(linear_reg_summary$r.squared, 6), "\n")
cat("  - Adjusted R-squared:", round(linear_reg_summary$adj.r.squared, 6), "\n")
cat("  - F-statistic:", round(linear_reg_summary$fstatistic[1], 3), "\n")
cat("  - p-value:", round(pf(linear_reg_summary$fstatistic[1], 
                            linear_reg_summary$fstatistic[2], 
                            linear_reg_summary$fstatistic[3], 
                            lower.tail = FALSE), 4), "\n")
cat("  - Slope (Beta 1):", round(coef(lm_fit)[2], 4), "\n")
cat("  - 95% CI for Beta 1: [", round(conf_intervals[2, 1], 4), ", ", 
    round(conf_intervals[2, 2], 4), "]\n\n")
                 
# the code displays summarized ANOVA test parameters, F-statistic, p-value, and Eta-squared effect size confidence bounds
cat("ANOVA Performance:\n")
cat("  - F-statistic:", round(anova_summary[[1]]$`F value`[1], 3), "\n")
cat("  - p-value:", round(anova_summary[[1]]$`Pr(>F)`[1], 4), "\n")
cat("  - Eta-squared:", round(eta$effsize[1], 6), "\n")
cat("  - 95% CI for Eta-squared: [", round(eta$conf.low[1], 6), ", ", 
    round(eta$conf.high[1], 6), "]\n\n")

# statistical test power analysis

# we use the the code to help calculate post-hoc statistical power for the ANOVA model based on sample size, 4 groups, and observed effect size (Cohen's f)                 

power_result <- pwr.anova.test(
  k = 4,
  n = nrow(analysis_df) / 4,
  f = sqrt(eta$effsize[1] / (1 - eta$effsize[1])),
  sig.level = 0.05
)
                 
# we run this code to see the statistical power and evaluate against the standard 0.80 benchmark for Type II error risk
                 
cat("Observed Statistical Power (ANOVA):\n")
cat("  - Power:", round(power_result$power, 4), "\n")
cat("  - Interpretation:", ifelse(power_result$power >= 0.80, 
    "Adequate power (>= 0.80)", 
    "Low power (< 0.80) - high risk of Type II error"), "\n\n")

# The code export the final dataset
                 
# exports a clean analysis_df dataset 
write.csv(analysis_df, "analysis_df_final.csv", row.names = FALSE)
  
sessionInfo()
                 
