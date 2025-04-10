-- Basic data overview
SELECT 
    COUNT(*) AS total_incidents,
    MIN(Year) AS first_year,
    MAX(Year) AS last_year,
    COUNT(DISTINCT Country) AS countries_affected,
    COUNT(DISTINCT Attack_Type) AS attack_types
FROM cyber_threats;

-- 2. COUNTRY-LEVEL ANALYSIS

-- Top 5 countries by total financial loss with percentage of global loss
WITH country_loss AS (
    SELECT 
        Country,
        SUM(Financial_Loss_Million) AS total_loss,
        SUM(Affected_Users) AS total_users_affected
    FROM cyber_threats
    GROUP BY Country
),
global_loss AS (
    SELECT SUM(Financial_Loss_Million) AS total_global_loss 
    FROM cyber_threats
)
SELECT 
    c.Country,
    c.total_loss,
    ROUND((c.total_loss * 100) / g.total_global_loss, 2) AS percentage_of_global_loss,
    c.total_users_affected,
    RANK() OVER (ORDER BY c.total_loss DESC) AS loss_rank
FROM country_loss c, global_loss g
ORDER BY c.total_loss DESC
LIMIT 5;

-- Country vulnerability analysis: most common vulnerability types per country
WITH RankedThreats AS (
    SELECT 
        Country,
        Vulnerability_Type,
        COUNT(*) AS incident_count,
        RANK() OVER (PARTITION BY Country ORDER BY COUNT(*) DESC) AS country_rank
    FROM cyber_threats
    GROUP BY Country, Vulnerability_Type
)
SELECT *
FROM RankedThreats
WHERE country_rank <= 3
ORDER BY Country, incident_count DESC;


-- 3. TIME TREND ANALYSIS

-- Yearly trends in cyber attacks (count, financial impact, resolution time)
SELECT 
    Year,
    COUNT(*) AS incident_count,
    SUM(Financial_Loss_Million) AS total_financial_loss,
    AVG(Financial_Loss_Million) AS avg_financial_loss,
    SUM(Affected_Users) AS total_users_affected,
    AVG(Incident_Resolution_Time_Hours) AS avg_resolution_time,
    -- Calculate year-over-year changes
    LAG(COUNT(*), 1) OVER (ORDER BY Year) AS prev_year_count,
    ROUND((COUNT(*) - LAG(COUNT(*), 1) OVER (ORDER BY Year)) * 100.0 / 
        LAG(COUNT(*), 1) OVER (ORDER BY Year), 2) AS yoy_change_count
FROM cyber_threats
GROUP BY Year
ORDER BY Year;

-- 4. ATTACK TYPE ANALYSIS

-- Attack type effectiveness (financial impact vs. resolution time)
SELECT 
    Attack_Type,
    COUNT(*) AS incident_count,
    SUM(Financial_Loss_Million) AS total_financial_loss,
    AVG(Financial_Loss_Million) AS avg_financial_loss,
    AVG(Incident_Resolution_Time_Hours) AS avg_resolution_time,
    -- Calculate severity score (combination of frequency, financial impact, and resolution time)
    ROUND((COUNT(*) * 0.3) + (SUM(Financial_Loss_Million) * 0.5) + 
          (AVG(Incident_Resolution_Time_Hours) * 0.2), 2) AS severity_score
FROM cyber_threats
GROUP BY Attack_Type
ORDER BY severity_score DESC;

-- Most targeted industries for each attack type
WITH ranked_attacks AS (
    SELECT 
        Attack_Type,
        Target_Industry,
        COUNT(*) AS incident_count,
        RANK() OVER (PARTITION BY Attack_Type ORDER BY COUNT(*) DESC) AS industry_rank
    FROM cyber_threats
    GROUP BY Attack_Type, Target_Industry
)
SELECT 
    Attack_Type,
    Target_Industry,
    incident_count
FROM ranked_attacks
WHERE industry_rank <= 2
ORDER BY Attack_Type, incident_count DESC;

-- 5. INDUSTRY IMPACT ANALYSIS

-- Industry vulnerability matrix
SELECT 
    Target_Industry,
    COUNT(*) AS total_incidents,
    SUM(Financial_Loss_Million) AS total_financial_loss,
    SUM(Affected_Users) AS total_users_affected,
    -- Most common attack type per industry
    (SELECT Attack_Type 
     FROM cyber_threats c2 
     WHERE c2.Target_Industry = c1.Target_Industry 
     GROUP BY Attack_Type 
     ORDER BY COUNT(*) DESC 
     LIMIT 1) AS most_common_attack,
    -- Most costly attack type per industry
    (SELECT Attack_Type 
     FROM cyber_threats c2 
     WHERE c2.Target_Industry = c1.Target_Industry 
     GROUP BY Attack_Type 
     ORDER BY SUM(Financial_Loss_Million) DESC 
     LIMIT 1) AS most_costly_attack
FROM cyber_threats c1
GROUP BY Target_Industry
ORDER BY total_financial_loss DESC;

-- 6. DEFENSE MECHANISM EFFECTIVENESS

-- Defense mechanism performance by attack type
SELECT 
    Attack_Type,
    Defense_Mechanism,
    COUNT(*) AS usage_count,
    AVG(Incident_Resolution_Time_Hours) AS avg_resolution_time,
    AVG(Financial_Loss_Million) AS avg_financial_loss,
    -- Effectiveness score (lower resolution time and financial loss is better)
    ROUND((100 - (AVG(Incident_Resolution_Time_Hours) * 0.7 + 
                 AVG(Financial_Loss_Million) * 0.3)), 2) AS effectiveness_score
FROM cyber_threats
GROUP BY Attack_Type, Defense_Mechanism
HAVING COUNT(*) >= 3  -- Only consider defenses used multiple times
ORDER BY Attack_Type, effectiveness_score DESC;

-- Most effective defense mechanisms overall
SELECT 
    Defense_Mechanism,
    COUNT(*) AS usage_count,
    AVG(Incident_Resolution_Time_Hours) AS avg_resolution_time,
    RANK() OVER (ORDER BY AVG(Incident_Resolution_Time_Hours)) AS resolution_rank,
    AVG(Financial_Loss_Million) AS avg_financial_loss,
    RANK() OVER (ORDER BY AVG(Financial_Loss_Million)) AS financial_rank
FROM cyber_threats
GROUP BY Defense_Mechanism
HAVING COUNT(*) >= 5
ORDER BY resolution_rank + financial_rank;

-- 7. ATTACK SOURCE ANALYSIS

-- Attack sources by sophistication (financial impact vs. resolution time)
SELECT 
    Attack_Source,
    COUNT(*) AS incident_count,
    AVG(Financial_Loss_Million) AS avg_financial_loss,
    AVG(Incident_Resolution_Time_Hours) AS avg_resolution_time,
    -- Sophistication score (higher financial impact and resolution time indicates more sophisticated attacks)
    ROUND((AVG(Financial_Loss_Million) * 0.6 + AVG(Incident_Resolution_Time_Hours) * 0.4), 2) AS sophistication_score
FROM cyber_threats
GROUP BY Attack_Source
ORDER BY sophistication_score DESC;

-- Attack source preferences (most used attack types per source)
WITH source_preferences AS (
    SELECT 
        Attack_Source,
        Attack_Type,
        COUNT(*) AS incident_count,
        RANK() OVER (PARTITION BY Attack_Source ORDER BY COUNT(*) DESC) AS preference_rank
    FROM cyber_threats
    GROUP BY Attack_Source, Attack_Type
)
SELECT 
    Attack_Source,
    Attack_Type,
    incident_count
FROM source_preferences
WHERE preference_rank <= 2
ORDER BY Attack_Source, incident_count DESC;

-- 8. VULNERABILITY ANALYSIS

-- Most exploited vulnerabilities with impact metrics
SELECT 
    Vulnerability_Type,
    COUNT(*) AS incident_count,
    SUM(Financial_Loss_Million) AS total_financial_loss,
    AVG(Financial_Loss_Million) AS avg_financial_loss,
    SUM(Affected_Users) AS total_users_affected,
    -- Most common attack type exploiting this vulnerability
    (SELECT Attack_Type 
     FROM cyber_threats c2 
     WHERE c2.Vulnerability_Type = c1.Vulnerability_Type 
     GROUP BY Attack_Type 
     ORDER BY COUNT(*) DESC 
     LIMIT 1) AS most_common_attack_type
FROM cyber_threats c1
GROUP BY Vulnerability_Type
ORDER BY total_financial_loss DESC;

-- 9. COMPREHENSIVE RISK ASSESSMENT

-- Combined risk assessment view
CREATE OR REPLACE VIEW cyber_risk_assessment AS
SELECT 
    Country,
    Year,
    Target_Industry,
    Attack_Type,
    Attack_Source,
    Vulnerability_Type,
    Financial_Loss_Million,
    Affected_Users,
    Incident_Resolution_Time_Hours,
    -- Risk score calculation
    ROUND(
        (Financial_Loss_Million * 0.4) + 
        (Affected_Users / 100000 * 0.3) + 
        (Incident_Resolution_Time_Hours * 0.3),
    2) AS risk_score,
    Defense_Mechanism
FROM cyber_threats;

-- Top 10 highest risk incidents
SELECT * FROM cyber_risk_assessment
ORDER BY risk_score DESC
LIMIT 10;

-- 10. PREDICTIVE ANALYSIS (for future trends)

-- Attack type trends over time (identify growing threats)
WITH yearly_attack_trends AS (
    SELECT 
        Year,
        Attack_Type,
        COUNT(*) AS incident_count,
        LAG(COUNT(*), 1) OVER (PARTITION BY Attack_Type ORDER BY Year) AS prev_year_count
    FROM cyber_threats
    GROUP BY Year, Attack_Type
)
SELECT 
    Attack_Type,
    Year,
    incident_count,
    prev_year_count,
    CASE 
        WHEN prev_year_count IS NULL THEN NULL
        ELSE ROUND(((incident_count - prev_year_count) * 100.0) / prev_year_count, 2)
    END AS yoy_growth
FROM yearly_attack_trends
ORDER BY yoy_growth IS NULL, yoy_growth DESC;



-- Industry risk projection based on historical trends
WITH industry_growth AS (
    SELECT 
        Target_Industry,
        Year,
        COUNT(*) AS incident_count,
        AVG(Financial_Loss_Million) AS avg_financial_loss,
        LAG(COUNT(*), 1) OVER (PARTITION BY Target_Industry ORDER BY Year) AS prev_year_count
    FROM cyber_threats
    GROUP BY Target_Industry, Year
)
SELECT 
    Target_Industry,
    Year,
    incident_count,
    prev_year_count,
    avg_financial_loss,
    CASE 
        WHEN prev_year_count IS NULL THEN NULL
        ELSE ROUND(((incident_count - prev_year_count) * 100.0) / prev_year_count, 2)
    END AS yoy_growth,
    -- Project next year's incidents based on average growth
    ROUND(incident_count * (1 + COALESCE(
        AVG(CASE 
            WHEN prev_year_count IS NULL THEN NULL
            ELSE (incident_count - prev_year_count) * 1.0 / prev_year_count
        END) OVER (PARTITION BY Target_Industry), 0)), 0) AS projected_next_year
FROM industry_growth
ORDER BY Target_Industry, Year;


