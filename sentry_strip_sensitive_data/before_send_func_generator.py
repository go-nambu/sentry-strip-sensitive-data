from typing import List


def generate_strip_sensitive_data(strip_key_list: List[str]):
    """
    Generate a function to filter sensitive data.
    Set the return value of this function to before_send of sentry.

    Parameters
    ----------
    strip_key_list : List[str]
        list of keys to strip

    Returns
    ----------
    function
    """
    def strip_sensitive_data(event, hint):
        for v in event["exception"]["values"]:
            for s in v["stacktrace"]["frames"]:
                s["vars"] = __recurse_filter_vars(s["vars"], strip_key_list)
        return event

    return strip_sensitive_data


def __recurse_filter_vars(obj, del_target_keys):
    for del_target_key in del_target_keys:
        if del_target_key in obj:
            del obj[del_target_key]
    for v in obj.values():
        if isinstance(v, dict):
            __recurse_filter_vars(v, del_target_keys)
        if isinstance(v, list):
            for e in v:
                if isinstance(e, dict):
                    __recurse_filter_vars(e, del_target_keys)
    return obj
