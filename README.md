# VIBE coded so no warranties!
The Vibe is strong on this one. The problem with Deptracks API is you can not:
- get a list of projects using a certain component only by its name. it does some kind of "like" in sql giving you too many things and you need to filter clientside. wouldn't be performant anyway with almost 10000 components.
- get a list of all components in deptrack. not possible for unknown reasons.
so we try the approach to get the list of projects and then for each project get the components.

# Shai-Hulud Package Analysis

This tool analyzes malicious packages from the Shai-Hulud CSV report and queries DependencyTrack to find projects using those packages.

## Features

The script gathers three types of statistics:
1. **Projects using the package (any version)**: All projects that have the package regardless of version
2. **Projects using exact malicious versions**: Projects using the specific version(s) marked as malicious in the CSV
3. **Projects using same major version**: Projects using a major version that aligns with the malicious package's major version

## Usage

### Using Docker

1. Build the Docker image:
```bash
docker build -t shai-hulud-analyzer .
```

2. Run the container with the DependencyTrack API token:
```bash
docker run --rm -e DT_API_TOKEN=your_token_here -e DT_BASE_URL=https://your-dependencytrack-instance.com -v $(pwd):/app/output shai-hulud-analyzer
```

The results will be saved to:
- `analysis_results.json`: Detailed statistics per package
- `projects_list.json`: Lists of project UUIDs for each category

### Using Python directly

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set the environment variables and run:
```bash
export DT_API_TOKEN=your_token_here
export DT_BASE_URL=https://your-dependencytrack-instance.com
python analyze_packages.py
```

## Output

The script generates two JSON files:

- **analysis_results.json**: Contains summary statistics and per-package details
- **projects_list.json**: Contains lists of project UUIDs for each category

## Environment Variables

- `DT_API_TOKEN`: Required. DependencyTrack API token for authentication.
- `DT_BASE_URL`: Required. DependencyTrack API base URL.
- `ENABLE_CACHE`: Optional. Enable caching of component data to `cache.json`. Set to `true`, `1`, or `yes` to enable. Defaults to disabled (cache is not used).

## Caching

The script supports caching component data to significantly speed up repeated runs. **Caching is disabled by default.**

### How It Works

When caching is enabled:
- Component data for each project is fetched from the DependencyTrack API and stored in `cache.json`
- On subsequent runs, cached data is loaded and used instead of making API calls
- The cache is saved incrementally every 10 projects and at the end of the run
- Projects already in the cache will show "(cached)" in the progress output

### Enabling Cache

**Using Docker:**
```bash
docker run --rm -e DT_API_TOKEN=your_token_here -e DT_BASE_URL=https://your-dependencytrack-instance.com -e ENABLE_CACHE=true -v $(pwd):/app/output shai-hulud-analyzer
```

**Using Python directly:**
```bash
export DT_API_TOKEN=your_token_here
export DT_BASE_URL=https://your-dependencytrack-instance.com
export ENABLE_CACHE=true
python analyze_packages.py
```

### Cache File Location

- **Docker**: Saved to `/app/output/cache.json` (mapped to your current directory via volume mount)
- **Local**: Saved to `./cache.json` in the current directory

### When to Use Cache

✅ **Enable cache when:**
- Running the analysis multiple times on the same set of projects
- Testing or debugging (avoids repeated API calls)
- Projects don't change frequently

❌ **Disable cache (default) when:**
- Running for the first time
- Projects or components have changed significantly
- You want fresh data from the API
- Cache file might be outdated

### Cache File Size

The cache file can grow large (tens of MB) depending on the number of projects and components. You can safely delete `cache.json` to start fresh.

