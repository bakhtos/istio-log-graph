import os
import json
from datetime import datetime, timedelta

ROOT_DIR = "kubernetes-istio-sleuth-v0.2.1-separate-load"
PPTAM_DIR = os.path.join(ROOT_DIR, 'pptam')
TRACING_DIR = os.path.join(ROOT_DIR, 'tracing-log')
TIME_DELTA = timedelta(hours=-8)


def detect_users(directory, time_delta=None):
    """Detect all Users appearing in locust logs.
    Each user must have an own directory with locust configuration/log.

    Parameters
    __________
    directory : str,
        A directory which stores all users' configurations and logs
    time_delta: datetime.timedelta, optional (default None)
        Time difference to add to all parsed timestamps (if None, defaults to 0
                                                         delta)

    Returns
    _______
    user_boundaries : dict[str] ->  tuple(datetime),
        for each user tells the couple of timestamps defining that user's
        beginning and end of activity;
    instance_boundaries : dict[str] -> dict[str] -> tuple[datetime],
        for each user stores the dictionary from user instances' uuids
        to the datetime of that instance's beginning of activity
    """

    # Default time_delta is 0
    if time_delta is None: time_delta = timedelta(0)

    def get_time(line):
        """Convert locustlog timestamp string to datetime object."""
        return datetime.fromisoformat('.'.join(line[1:24].split(',')))

    # Each user is defined by a separate directory
    users = os.listdir(directory)
    instance_boundaries = dict()
    user_boundaries = dict()

    for user in users:
        # Read locustlog of a user
        locustlog = os.path.join(directory, user, 'locustfile.log')
        with open(locustlog, 'r') as file:
            lines = file.readlines()

        # First and last timestamps in file define the interval when the user was active
        user_boundaries[user] = (get_time(lines[0])+time_delta, get_time(lines[-1])+time_delta)

        # Each line with 'Running user' begins a new instance of the particular user
        user_instance_boundaries = dict()
        instance = None
        for line in lines:
            if "Running user" in line:
                t = get_time(line) + time_delta
                end_time = t
                if instance is not None:
                    user_instance_boundaries[instance] = start_time, end_time
                instance = line[-40:-4]
                start_time = t

        user_instance_boundaries[instance] = start_time, user_boundaries[user][1]
        instance_boundaries[user] = user_instance_boundaries
        print(f"{user}: {len(user_instance_boundaries)} instances detected")

    return user_boundaries, instance_boundaries


def create_edgelists(directory, user_boundaries, instance_boundaries):
    """Parse tracing logs to get call counts and edgelists.

    Parameters
    __________
    directory : str,
        Directory containing tracing log file for each microservice.
    user_boundaries : dict[str] -> tuple[datetime],
        Temporal boundaries of each user as returned by detect_users().
    instance_boundaries : dict[str] -> dict[str] -> tuple[datetime],
        Temporal boundaries of each user instance as returned by detect_users().

    Returns
    _______
    edgelists : dict[str] -> list[tuple[datetime, str, str, str]],
        For each user[_instance]  list of tuples containing the datetime of
        the call, calling service, called service and called endpoint,
        sorted by the time of call.
    """

    edgelists = dict()
    services = os.listdir(directory)
    for from_service in services:
        # Read log line by line
        f = open(os.path.join(directory, from_service), 'r')
        from_service = from_service.split('.')[0]
        for line in f:
            # Parse lines containing json bodies
            if line[0] == '{':
                obj = json.loads(line)
                # Get the time of the API call
                start_time = obj["start_time"]
                start_time = datetime.fromisoformat(start_time[:-1])

                # Find correct user
                user = None
                for user, boundaries in user_boundaries.items():
                    if boundaries[0] <= start_time < boundaries[1]:
                        break
                if user is None: continue

                # Find the correct user instance
                user_instance = None
                for user_instance, boundaries in instance_boundaries[user].items():
                    if boundaries[0] <= start_time < boundaries[1]:
                        break
                if user_instance is None: continue

                user_instance = user + '_' + user_instance
                user = user + '_total'
                # Insert user[_instance] in all necessary datastructures
                edgelists.setdefault(user, [])
                edgelists.setdefault(user_instance, [])

                # If calling another service, store the call and the pipeline
                to_service = obj["upstream_cluster"]
                to_service = to_service.split('|')
                if to_service[0] == 'outbound':
                    to_service = to_service[3].split('.')[0]
                    endpoint = obj['path']
                    if endpoint is None: endpoint = '/'
                    endpoint = endpoint.split('/')
                    endpoint = '/'.join(endpoint[0:5])

                    edgelists[user].append((from_service, to_service,
                                            endpoint, start_time.isoformat()))
                    edgelists[user_instance].append((from_service, to_service,
                                                     endpoint, start_time.isoformat()))
        f.close()

    for pipeline in edgelists.values():
        pipeline.sort(key=lambda x: x[0])

    return edgelists


def write_edgelists(edgelists):
    """Write each user[_instance]'s pipeline to a csv file."""

    os.makedirs("edgelists", exist_ok=True)

    for k, l in edgelists.items():
        p = os.path.join("edgelists", k+".edgelist")
        file = open(p, 'w')
        for t in l:
            file.write(' '.join(t)+'\n')
        file.close()


def extract_graphs(pptam_dir, tracing_dir, time_delta):
    """Create call graphs and edgelists based on logs location.

    Parameters
    __________
    pptam_dir - str,
        Directory storing directories with pptam/locust configurations and
        logs for each user (will be passed to detect_users()).
    tracing_dir - str,
        Directory containing tracing logs for each microservice (will be
        passed to parse_logs()).
    time_delta - datetime.timedelta,
        Corrective timedelta to add to all timestamps in locust log (will be
        passed to detect_users()).
    """
    user_boundaries, instance_boundaries = detect_users(pptam_dir, time_delta)

    # Get calls and edgelists for each user using logs of each service
    edgelists = create_edgelists(tracing_dir, user_boundaries,
                                 instance_boundaries)
    write_edgelists(edgelists)


if __name__ == '__main__':
    extract_graphs(PPTAM_DIR, TRACING_DIR, TIME_DELTA)
