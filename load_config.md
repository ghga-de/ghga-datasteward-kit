# LoadConfig


*Load Config*


## Properties


- **`event_store_path`** *(string)*: Path of the directory on the file system where all events are stored. Each topic is a sub-directory. Each event is stored as a JSON file within the sub-directory for the topic. The file name corresponds to the event key. The event type is stored together with the payload in the event file.

- **`artifact_topic_prefix`** *(string)*: The prefix used for topics containing artifacts. The topic name is expected to be '{prefix}.{artifact_type}'. The prefix must not contain dots.

- **`artifact_types`** *(array)*: The artifacts types of interest. Together with the topic prefix, they determine the topics to subscribe to. The artifact types must not contain dots.

  - **Items** *(string)*

- **`loader_api_root`** *(string)*: Root URL of the loader API.
