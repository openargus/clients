# Argus Clients Architecture

This document describes the architecture of the Argus clients ecosystem - the tools for reading, processing, analyzing, and managing Argus flow data.

---

## System Overview

Argus clients provide a comprehensive suite of tools for flow data processing, analysis, and management.

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Argus Clients Ecosystem                              │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    Core Processing Tools                        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                        │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐       │
│  │    ra       │ │  radump     │ │   rasort    │ │  ragrep     │       │
│  │  (viewer)   │ │ (inspect)   │ │  (sort)     │ │ (filter)    │       │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘       │
│                                                                        │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐       │
│  │ racluster   │ │   rasum     │ │  rahisto    │ │  rahosts    │       │
│  │(aggregate)  │ │ (summary)   │ │(histogram)  │ │ (resolve)   │       │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘       │
│                                                                        │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐       │
│  │ raconvert   │ │ ranonymize  │ │  ralabel    │ │  rastream   │       │
│  │ (convert)   │ │ (privacy)   │ │ (enrich)    │ │ (stream)    │       │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘       │
│                                                                        │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐       │
│  │   ragraph   │ │   rasql     │ │   radium    │ │  ramanage   │       │
│  │  (graph)    │ │  (SQL)      │ │  (monitor)  │ │ (archive)   │       │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘       │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Component Architecture

### Core Client Library

| Component    | File                   | Lines | Responsibility                  |
|--------------|------------------------|-------|---------------------------------|
| Client Core  | `argus_client.c`       |  710K | Main client library, record I/O |
| Utilities    | `argus_util.c`         |  1.1M | Common utilities, formatting    |
| Output       | `argus_output.c`       |  235K | Output formatting, display      |
| Filter       | `argus_filter.c`       |   87K | Filter expression evaluation    |
| Code         | `argus_code.c`         |  172K | Data encoding/decoding          |
| Labeling     | `argus_label.c`        |  224K | Flow labeling, classification   |
| Import       | `argus_import.c`       |  185K | Import from other formats       |
| JSON         | `argus_json.c`         |   23K | JSON output support             |
| GeoIP        | `argus_label_geoip.c`  |   43K | Geographic IP lookup            |
| Auth         | `argus_auth.c`         |   20K | Authentication, encryption      |
| Grep         | `argus_grep.c`         |    5K | Pattern matching                |
| Timer        | `argus_timer.c`        |    9K | Time-based operations           |
| Event        | `argus_event.c`        |   31K | Event processing                |
| Parser       | `argus_parser.c`       |   12K | Command-line parsing            |
| Main         | `argus_main.c`         |   17K | Common main() logic             |
| Config       | `argus_clientconfig.c` |    5K | Client configuration            |
| Lockfile     | `argus_lockfile.c`     |    7K | Process locking                 |
| Split Mode   | `argus_split_mode.c`   |    9K | File splitting logic            |
| Time Parse   | `argus_parse_time.c`   |   20K | Time expression parsing         |

### Client Tools

| Tool          | File              | Lines | Purpose                     |
|---------------|-------------------|-------|-----------------------------|
| ra            | `ra.c`            |   31K | Main flow viewer/filter     |
| radump        | `radump.c`        |     - | File format inspection      |
| racluster     | `racluster.c`     |   54K | Flow aggregation/clustering |
| rasort        | `rasort.c`        |   18K | Sort flow records           |
| racount       | `racount.c`       |   42K | Count flows by criteria     |
| raconvert     | `raconvert.c`     |     - | Format conversion           |
| rasum         | `rasum.c`         |     - | Summary statistics          |
| rahisto       | `rahisto.c`       |     - | Histogram generation        |
| rahosts       | `rahosts.c`       |     - | Host resolution             |
| ragrep        | `ragrep.c`        |     - | Pattern filtering           |
| rafilter      | `rafilter.c`      |     - | Address filtering           |
| ralabel       | `ralabel.c`       |     - | Flow labeling               |
| ranonymize    | `ranonymize.c`    |   81K | Data anonymization          |
| rastream      | `rastream.c`      |   61K | Stream processing           |
| raevent       | `raevent.c`       |     - | Event processing            |
| rascore       | `rascore.c`       |     - | Scoring/anomaly detection   |
| rapolicy      | `rapolicy.c`      |     - | Policy enforcement          |
| rapath        | `rapath.c`        |     - | Path analysis               |
| ramatrix      | `ramatrix.c`      |     - | Traffic matrix              |
| rarpwatch     | `rarpwatch.c`     |     - | ARP monitoring              |
| radecode      | `radecode.c`      |     - | Packet decoding             |
| rabins        | `rabins.c`        |   54K | Process using time bins     |
| radbaserollup | `radbaserollup.c` |     - | Database aggregation        |
| raclique      | `raclique.c`      |     - | Clique detection            |
| raqsort       | `raqsort.c`       |     - | Quick sort                  |
| raservices    | `raservices.c`    |     - | Service identification      |
| raports       | `raports.c`       |     - | Port analysis               |
| radium        | `radium.c`        |   32K | Argus data redistribution   |
| radns         | `radns.c`         |     - | DNS processing              |
| radnsdb       | `radnsdb.c`       |     - | DNS database                |
| ramanage      | `ramanage.c`      |   61K | Archive management          |
| rasql         | `rasql.c`         |     - | SQL interface               |
| ragraph       | `ragraph.c`       |     - | Graph generation            |
| raplot        | `raplot.c`        |     - | Plot generation             |

### Common Libraries

| Component       | File        | Responsibility                 |
|-----------------|-------------|--------------------------------|
| Scanner         | `scanner.l` | Filter expression lexer        |
| Grammar         | `grammar.y` | Filter expression parser       |
| SHA1            | `sha1.c`    | SHA1 hashing                   |
| Ring Buffer     | `ring.c`    | Circular buffer implementation |
| Version         | `version.c` | Build version info             |

---

## Data Flow Architecture

### Flow Processing Pipeline

```
┌──────────────────────────────────────────────────────────────────────┐
│                       Client Processing Flow                         │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  INPUT SOURCE                                                        │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │ • Argus flow file (/var/log/argus/*.argus)                    │   │
│  │ • Socket stream (live data from argus daemon)                 │   │
│  │ • Standard input (piped data)                                 │   │
│  │ • Compressed file (.gz)                                       │   │
│  └───────────────────────────┬───────────────────────────────────┘   │
│                              ▼                                       │
│  RECORD READING (argus_client.c)                                     │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │ • File header validation                                      │   │
│  │ • Record parsing (binary format)                              │   │
│  │ • DSR block extraction                                        │   │
│  │ • Format conversion (if needed)                               │   │
│  └───────────────────────────┬───────────────────────────────────┘   │
│                              ▼                                       │
│  FILTERING (argus_filter.c, argus_grep.c)                            │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │ • Time range filtering                                        │   │
│  │ • Address filtering (source/destination)                      │   │
│  │ • Protocol filtering                                          │   │
│  │ • Port filtering                                              │   │
│  │ • Pattern matching (grep)                                     │   │
│  └───────────────────────────┬───────────────────────────────────┘   │
│                              ▼                                       │
│  TRANSFORMATION (argus_util.c)                                       │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │ • Field selection                                             │   │
│  │ • Data enrichment (DNS, GeoIP)                                │   │
│  │ • Address anonymization                                       │   │
│  │ • Protocol decoding                                           │   │
│  │ • Labeling/classification                                     │   │
│  └───────────────────────────┬───────────────────────────────────┘   │
│                              ▼                                       │
│  AGGREGATION (racluster.c, rasum.c)                                  │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │ • Time-based aggregation                                      │   │
│  │ • Address-based clustering                                    │   │
│  │ • Protocol aggregation                                        │   │
│  │ • Statistical summaries                                       │   │
│  │ • Histogram generation                                        │   │
│  └───────────────────────────┬───────────────────────────────────┘   │
│                              ▼                                       │
│  OUTPUT FORMATTING (argus_output.c)                                  │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │ • Tabular display (default)                                   │   │
│  │ • CSV format                                                  │   │
│  │ • JSON format                                                 │   │
│  │ • Binary output                                               │   │
│  │ • Graph/plot data                                             │   │
│  │ • SQL insert statements                                       │   │
│  └───────────────────────────┬───────────────────────────────────┘   │
│                              ▼                                       │
│  OUTPUT DESTINATION                                                  │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │ • Standard output (terminal)                                  │   │
│  │ • File (with rotation)                                        │   │
│  │ • Database (MySQL, PostgreSQL)                                │   │
│  │ • Socket (stream to another process)                          │   │
│  │ • Graphing tool (gnuplot, etc.)                               │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Tool Categories

### 1. Data Viewing & Filtering

| Tool           | Primary Use        | Key Options                     |
|----------------|--------------------|---------------------------------|
| ra             | View and filter    | `-o` (output fields),           |
|                | flows              | `-s` (sort), `-M` (format)      |
| radump         | tcpdump format     | `-v` (verbose),                 |
|                |                    | `-R` (raw)                      |
| ragrep         | Pattern matching   | `-s` (search field),            |
|                |                    | `-p` (pattern)                  |
| rafilter       | Address filtering  | `-s` (source),                  |
|                |                    | `-d` (destination)              |

### 2. Aggregation & Analysis

| Tool           | Primary Use        | Key Options                     |
|----------------|--------------------|---------------------------------|
| racluster      | Cluster flows      | `-n` (time window), `-k` (keys) |
| rasum          | Summary statistics | `-n` (interval), `-M` (format)  |
| rahisto        | Histograms         | `-k` (field), `-n` (buckets)    |
| racount        | Count flows        | `-k` (grouping), `-n` (limit)   |
| ramatrix       | Traffic matrix     | `-s` (source), `-d` (dest)      |

### 3. Data Transformation

| Tool           | Primary Use        | Key Options                     |
|----------------|--------------------|---------------------------------|
| raconvert      | Format conversion  | `-F` (input), `-f` (output)     |
| ranonymize     | Privacy protection | `-k` (key), `-s` (scope)        |
| ralabel        | Flow labeling      | `-l` (label file), `-m` (match) |
| rasort         | Sort records       | `-k` (key), `-r` (reverse)      |
| raqsort        | Quick sort         | `-k` (key), `-n` (limit)        |

### 4. Enrichment & Resolution

| Tool           | Primary Use        | Key Options                     |
|----------------|--------------------|---------------------------------|
| rahosts        | DNS resolution     | `-r` (resolve), `-R` (reverse)  |
| radns          | DNS analysis       | `-q` (query), `-a` (answer)     |
| ralabel        | Classification     | `-l` (labels), `-c` (config)    |
| raevent        | Event processing   | `-e` (event type)               |

### 5. Visualization & Reporting

| Tool           | Primary Use        | Key Options                     |
|----------------|--------------------|---------------------------------|
| ragraph        | Graph generation   | `-t` (type), `-o` (output)      |
| raplot         | Plot data          | `-f` (format), `-o` (output)    |
| rahisto        | Histograms         | `-k` (field), `-n` (buckets)    |
| raports        | Port analysis      | `-p` (ports), `-s` (summary)    |

### 6. Storage & Management

| Tool           | Primary Use        | Key Options                     |
|----------------|--------------------|---------------------------------|
| ramanage       | Archive management | `-a` (archive), `-r` (rotate)   |
| rasql          | SQL interface      | `-h` (host), `-d` (database)    |
| rastream       | Stream processing  | `-S` (socket), `-w` (write)     |
| radbaserollup  | DB aggregation     | `-t` (table), `-i` (interval)   |

### 7. Specialized Analysis

| Tool           | Primary Use        | Key Options                     |
|----------------|--------------------|---------------------------------|
| rapolicy       | Policy enforcement | `-p` (policy), `-a` (action)    |
| rascore        | Anomaly scoring    | `-m` (model), `-t` (threshold)  |
| rapath         | Path analysis      | `-i` (interface), `-n` (nodes)  |
| rarpwatch      | ARP monitoring     | `-i` (interface), `-w` (write)  |
| radium         | Record distribution| `-a` (auth), `-r` (req)         |
| rabins         | Binary analysis    | `-b` (binary), `-s` (stats)     |

---

## Language Bindings

### Python Library

```
pythonlib/
├── argusPython.c      # SWIG Python bindings
├── argusPython.h      # Header for Python API
├── argusPython.i      # SWIG interface file
├── numpy.i            # NumPy array support
├── setup.py           # Python package setup
└── test/              # Python test suite
```

Usage Example:
```python
import argus

# Open flow file
reader = argus.ArgusReader('data.argus')

# Iterate through records
for record in reader:
    print(f"{record.src} -> {record.dst}")
```

### Perl Library

```
perllib/
├── qosient/           # Perl module
│   └── argus.pm       # Argus Perl API
├── swig_ArgusParseTime.c  # SWIG bindings
└── swig_ArgusParseTime.i  # SWIG interface
```

---

## Build System

### Directory Structure

```
clients/
├── clients/           # Client tool source
│   ├── ra.c          # Main viewer
│   ├── racluster.c   # Aggregation
│   ├── radump.c      # File inspection
│   └── ...           # Other tools
├── common/            # Shared libraries
│   ├── argus_client.c    # Core client library
│   ├── argus_util.c      # Utilities
│   ├── argus_output.c    # Output formatting
│   ├── argus_label.c     # Labeling
│   ├── grammar.y         # Filter parser
│   └── scanner.l         # Filter lexer
├── include/           # Header files
│   ├── argus/         # Client-specific headers
│   └── *.h            # Protocol headers
├── bin/               # Compiled binaries
├── man/               # Manual pages
├── examples/          # Example configurations
│   ├── raconvert/     # Conversion examples
│   ├── radump/        # Inspection examples
│   └── ...            # Tool-specific examples
├── pythonlib/         # Python bindings
├── perllib/           # Perl bindings
└── pkg/               # Package files
```

### Build Process

```bash
./configure              # Detect system capabilities
make                     # Build all components
make check               # Run tests
sudo make install        # Install to system
```

---

## Configuration Architecture

### Client Configuration

```
┌─────────────────────────────────────┐
│ 1. Command-Line Options             │  ← Highest Priority
├─────────────────────────────────────┤
│ 2. Environment Variables            │
│    ARGUSPATH, ARGUSHOME             │
├─────────────────────────────────────┤
│ 3. User Config Files                │
│    ~/.ra.rc, ~/.racluster.rc        │
├─────────────────────────────────────┤
│ 4. System Config Files              │
│    /etc/ra.rc, /etc/racluster.rc    │
├─────────────────────────────────────┤
│ 5. Compiled-in Defaults             │  ← Lowest Priority
└─────────────────────────────────────┘
```

### Common Configuration Files

| File           | Purpose              | Location                      |
|----------------|----------------------|-------------------------------|
| `ra.rc`        | Default ra options   | ~/.ra.rc, /etc/ra.rc          |
| `excel.rc`     | CSV format for Excel | /etc/excel.rc                 |
| `label.rc`     | Flow labeling rules  | ~/.label.rc                   |

---

## Performance Characteristics

### Tool Performance

| Tool           | Throughput    | Memory    | Notes                    |
|----------------|---------------|--------------------------------------|
| ra             | 100K+ r/s     |  50-500MB | Depends on filters       |
| radump         | 50K+ r/s      |  10-100MB | Raw format parsing       |
| racluster      | 50K+ r/s      | 100MB-2GB | Depends on aggregation   |
| rasum          | 200K+ r/s     |  50-200MB | Simple aggregation       |
| raconvert      | 100K+ r/s     |  50-100MB | Format conversion        |

### Optimization Strategies

1. Streaming Processing
   - Process records one at a time
   - Minimize memory footprint
   - Pipeline tools with pipes

2. Indexing
   - Use time-based indexes for random access
   - Pre-compute aggregations

3. Parallel Processing
   - Multiple tools can run in parallel
   - Split large files for concurrent processing

---

## Integration Points

### With Argus Daemon

```
┌───────────────┐          ┌──────────────┐
│     argus     │─────────►│      ra      │
│      (C)      │  stream  │   (Clients)  │
│               │          │              │
│  File Output  │─────────►│    radump    │
└───────────────┘          └──────────────┘
```

### With External Systems

- Databases: MySQL, PostgreSQL via rasql
- Graphing: gnuplot via ragraph/raplot
- SIEM: Syslog, CEF output via raconvert
- Python: Data analysis via Python bindings
- Perl: Custom processing via Perl bindings

---

## Related Documentation

- [argus.8](../man/man8/argus.8) - Daemon command reference
- [argus.conf.5](../man/man5/argus.conf.5) - Configuration reference
- [../ARCHITECTURE.md](../ARCHITECTURE.md) - Daemon architecture
- [INSTALL](INSTALL) - Build instructions
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development guidelines

---

*Last updated: 2026-07-02*
*Argus Clients Version: 5.0.x*
