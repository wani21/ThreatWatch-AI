import math

def calculate_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate the great-circle distance between two points on the Earth's surface
    using the Haversine formula.
    
    Returns the distance in kilometers.
    """
    # Radius of the Earth in kilometers
    R = 6371.0
    
    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)
    
    dlat = lat2_rad - lat1_rad
    dlon = lon2_rad - lon1_rad
    
    a = (math.sin(dlat / 2) ** 2) + math.cos(lat1_rad) * math.cos(lat2_rad) * (math.sin(dlon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    
    return R * c


def calculate_required_speed(distance_km: float, time_diff_seconds: float) -> float:
    """
    Calculate the required speed in km/h to cover a given distance in seconds.
    If the time difference is 0 or negative, returns 0.0.
    """
    if time_diff_seconds <= 0:
        return 0.0
        
    time_diff_hours = time_diff_seconds / 3600.0
    return distance_km / time_diff_hours
