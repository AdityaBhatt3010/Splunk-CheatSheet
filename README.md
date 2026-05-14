# Splunk SPL Cheat Sheet (Practical SOC / Threat Hunting Edition) 🗿

---

# 1. Basic Search

Search entire index:

```spl
index=windowslogs
```

Meaning:

Search all events inside the `windowslogs` dataset.

---

Search keyword:

```spl
index=windowslogs powershell
```

Meaning:

Find events containing:

```text
powershell
```

---

Exact phrase:

```spl
index=windowslogs "failed login"
```

Meaning:

Find exact phrase.

Order matters.

---

Multiple keywords:

```spl
index=windowslogs malware ransomware
```

Meaning:

Both words must exist.

---

# 2. Field Filtering

Exact match:

```spl
User=Aditya
```

Not equal:

```spl
User!=SYSTEM
```

Greater than:

```spl
Bytes>1000
```

Less than:

```spl
Age<10
```

Greater or equal:

```spl
Count>=50
```

Less or equal:

```spl
Count<=20
```

---

# 3. Logical Operators

AND:

```spl
User=James AND EventID=4624
```

Both conditions true.

---

OR:

```spl
User=James OR User=Alice
```

Either condition true.

---

NOT:

```spl
NOT User=SYSTEM
```

Exclude SYSTEM.

---

IN:

```spl
User IN (James, Alice, Bob)
```

Cleaner OR alternative.

---

# 4. Wildcards

Starts with:

```spl
User=adm*
```

Matches:

```text
admin
administrator
adm_root
```

---

Contains:

```spl
CommandLine=*powershell*
```

Matches:

```text
run powershell
powershell.exe
abc powershell xyz
```

---

IP partial:

```spl
SourceIp=172.*
```

---

Subnet:

```spl
SourceIp=172.18.0.0/16
```

---

# 5. Useful Windows Event IDs

Successful login:

```spl
EventID=4624
```

Failed login:

```spl
EventID=4625
```

Process creation (Sysmon):

```spl
EventID=1
```

Network connection:

```spl
EventID=3
```

Registry modification:

```spl
EventID=13
```

Service creation:

```spl
EventID=7045
```

PowerShell Script Block Logging:

```spl
EventID=4104
```

---

# 6. Time Filtering

Last 24 hours:

```spl
earliest=-24h
```

Last 7 days:

```spl
earliest=-7d
```

Specific range:

```spl
earliest="04/15/2022:08:05:00" latest="04/15/2022:08:06:00"
```

Example:

```spl
index=windowslogs earliest=-1h
```

---

# 7. fields Command

Show only chosen fields:

```spl
| fields User SourceIp EventID
```

Before:

| User | SourceIp | EventID | Host | CommandLine |
| ---- | -------- | ------- | ---- | ----------- |

After:

| User | SourceIp | EventID |

---

Exclude field:

```spl
| fields - CommandLine
```

---

# 8. table Command

Readable output:

```spl
| table _time User SourceIp EventID
```

Example:

| Time | User | IP | Event |
| ---- | ---- | -- | ----- |

SOC reporting favorite.

---

# 9. stats Command

## What does stats do?

It summarizes data.

But destroys original raw rows.

Example raw data:

| Time  | User   | Country |
| ----- | ------ | ------- |
| 10:00 | kbrown | US      |
| 10:05 | kbrown | US      |
| 10:10 | jsmith | JP      |

Query:

```spl
| stats count by User
```

Breakdown:

* count events
* group by user

Result:

| User   | count |
| ------ | ----- |
| kbrown | 2     |
| jsmith | 1     |

Notice:

Original rows vanished.

No timestamps.
No countries.

Only summary remains.

---

Count by field:

```spl
| stats count by SourceIp
```

Average:

```spl
| stats avg(Bytes)
```

Max:

```spl
| stats max(Bytes)
```

Min:

```spl
| stats min(Bytes)
```

Sum:

```spl
| stats sum(Bytes)
```

Multiple:

```spl
| stats count avg(Bytes) max(Bytes) by User
```

---

# 10. eventstats Command

## What does eventstats do?

Same calculations as stats.

BUT keeps original events.

Raw data:

| Time  | User   | Country |
| ----- | ------ | ------- |
| 10:00 | kbrown | US      |
| 10:05 | kbrown | US      |
| 10:10 | jsmith | JP      |

Query:

```spl
| eventstats count by User
```

Result:

| Time  | User   | Country | count |
| ----- | ------ | ------- | ----- |
| 10:00 | kbrown | US      | 2     |
| 10:05 | kbrown | US      | 2     |
| 10:10 | jsmith | JP      | 1     |

Difference:

`stats`

→ replace rows

`eventstats`

→ enrich rows

---

Another example:

Raw:

| User   | Country |
| ------ | ------- |
| kbrown | US      |
| kbrown | US      |
| kbrown | JP      |

Query:

```spl
| eventstats count by user src_country
```

Result:

| User   | Country | count |
| ------ | ------- | ----- |
| kbrown | US      | 2     |
| kbrown | US      | 2     |
| kbrown | JP      | 1     |

This is why anomaly detection uses eventstats.

Because raw rows must survive.

---

Memory trick:

```text
stats = summarize & replace
eventstats = summarize & keep
```

---

# 11. top / rare

Most frequent:

```spl
| top User
```

Example:

| User   | count |
| ------ | ----- |
| SYSTEM | 500   |

---

Top 5:

```spl
| top User limit=5
```

---

Least frequent:

```spl
| rare User
```

Good for anomaly hunting.

---

# 12. sort

Ascending:

```spl
| sort User
```

Descending:

```spl
| sort - count
```

Highest first.

---

# 13. reverse

Flip order:

```spl
| reverse
```

Good for timelines.

---

# 14. head / tail

Newest first 10:

```spl
| head 10
```

Oldest last 10:

```spl
| tail 10
```

---

# 15. dedup

Remove duplicates:

```spl
| dedup SourceIp
```

Before:

```text
1.1.1.1
1.1.1.1
2.2.2.2
```

After:

```text
1.1.1.1
2.2.2.2
```

---

# 16. rename

Rename fields:

```spl
| rename User as Employee
```

Before:

| User |

After:

| Employee |

---

# 17. regex

Ends with exe:

```spl
| regex Image="\.exe$"
```

Contains powershell:

```spl
| regex CommandLine=".*powershell.*"
```

Starts with admin:

```spl
| regex User="^admin"
```

---

# 18. eval

Create field:

```spl
| eval status="Suspicious"
```

Math:

```spl
| eval total=sent+received
```

If logic:

```spl
| eval verdict=if(Bytes>1000,"High","Normal")
```

Case:

```spl
| eval type=case(
EventID=4624,"Success",
EventID=4625,"Failure"
)
```

---

# 19. where

Filter after calculations:

```spl
| where count > 10
```

Example:

```spl
| stats count by User
| where count > 5
```

---

# 20. chart

Visualization summary:

```spl
| chart count by User
```

---

# 21. timechart

Trend over time:

```spl
| timechart count
```

30 min bins:

```spl
| timechart span=30m count
```

Top processes:

```spl
| timechart span=30m count by Image
```

---

# 22. iplocation

Geo enrichment:

```spl
| iplocation SourceIp
```

Example:

| IP | Country | Region |
| -- | ------- | ------ |

Then:

```spl
| stats count by Country
```

---

# 23. lookup

External enrichment:

```spl
| lookup image_riskscore Image OUTPUT RiskScore
```

Uses:

* threat intel
* IOC CSVs
* asset criticality
* employee role mappings

---

# 24. join

Correlation:

```spl
| join LogonId
```

Example:

Process + authentication correlation.

Heavy query.

---

# 25. subsearch

Nested search:

```spl
[ search index=windowslogs EventID=4624 ]
```

Example:

```spl
index=windowslogs EventID=1
| join LogonId
    [ search index=windowslogs EventID=4624 ]
```

---

# 26. highlight

Visual marking:

```spl
| highlight powershell malware cmd.exe
```

Useful in raw view.

---

# 27. Anomaly Detection Patterns

Rare country:

```spl
| eventstats count by user
| eventstats count by user src_country
| eval freq=country_count/user_count
| where freq < 0.1
```

Weird login hour:

```spl
| eventstats avg(hour) stdev(hour) by user
| eval zscore=abs(hour-avg)/stdev
| where zscore > 3
```

---

# 28. Threat Hunting Queries

PowerShell:

```spl
index=windowslogs powershell
```

Encoded PS:

```spl
CommandLine=*EncodedCommand*
```

LOLBins:

```spl
Image IN ("cmd.exe","powershell.exe","mshta.exe","certutil.exe")
```

Failed auth:

```spl
EventID=4625
```

Admin success login:

```spl
EventID=4624 User=Administrator
```

Suspicious parent:

```spl
EventID=1 ParentImage=*powershell*
```

---

# 29. Practical Pipeline Logic

Think:

```text
SEARCH → FILTER → SUMMARIZE → CALCULATE → FORMAT
```

Example:

```spl
index=windowslogs EventID=4624
| stats count by User
| where count > 10
| sort - count
| table User count
```

Meaning:

* find successful logins
* count per user
* keep noisy users
* sort descending
* clean report

---

# Mental Model

```text
search = find
fields = select
table = display
stats = summarize & replace
eventstats = summarize & keep
eval = calculate
where = filter after calc
top = common
rare = uncommon
lookup = enrich
iplocation = geo enrich
regex = pattern match
timechart = trends
```

---
