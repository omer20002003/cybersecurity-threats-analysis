CREATE DATABASE cybersecurity_threats;
USE cybersecurity_threats;

CREATE TABLE IF NOT EXISTS cyber_threats (
    Country VARCHAR(50),
    Year INT,
    Attack_Type VARCHAR(50),
    Target_Industry VARCHAR(50),
    Financial_Loss_Million DECIMAL(10, 2),
    Affected_Users INT,
    Attack_Source VARCHAR(50),
    Vulnerability_Type VARCHAR(50),
    Defense_Mechanism VARCHAR(50),
    Incident_Resolution_Time_Hours INT
);