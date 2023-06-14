# SubmissionAndTransformationConfig


*Config parameters used for submission and transformation of metadata.*


## Properties


- **`source_event_topic`** *(string)*: Name of the topic to which source events are published. Default: `source_events`.

- **`source_event_type`** *(string)*: Name of the event type for source events. Default: `source_event`.

- **`artifact_topic_prefix`** *(string)*: The prefix used for topics containing artifacts. The topic name is expected to be '{prefix}.{artifact_type}'. The prefix must not contain dots.

- **`event_store_path`** *(string)*: Path of the directory on the file system where all events are stored. Each topic is a sub-directory. Each event is stored as a JSON file within the sub-directory for the topic. The file name corresponds to the event key. The event type is stored together with the payload in the event file.

- **`accession_store_path`** *(string)*: A file for storing the already registered accessions.

- **`prefix_mapping`** *(object)*: Specifies the ID prefix (values) per resource type (keys). Can contain additional properties.

  - **Additional Properties** *(string)*

- **`suffix_length`** *(integer)*: Length of the numeric ID suffix. Default: `8`.

- **`metadata_model_path`** *(string)*: The path to the metadata model defined in LinkML.

- **`submission_store_dir`** *(string)*: The directory where the submission JSONs will be stored.

- **`workflow_config`**: Configuration for the metadata transfornation workflow.

## Definitions


- **`AccessionAdditionConfig`** *(object)*: Config to add accessions to a model and associated metadata. Cannot contain additional properties.

  - **`accession_slot_name`** *(string)*: The name of the slot to contain the accessions to. Default: `accession`.

  - **`accession_slot_description`** *(string)*: The description of the slot to contain the accessions to. Default: `The accession for an entity.`.

- **`EmbeddingProfile`** *(object)*: A model for describing a profile for embedding referenced classes into a class
of interest of a metadata model. Please note, only the embedding for anchored
classes that are referenced by this source class can be changed. All anchored
classes are assumed to be non-embedded by default. The embedding profile can be used
to define anchored classes as embedded given the slot named used for renferencing
in the source class.

  - **`target_class`** *(string)*: The name of the transformed class with embeddings.

  - **`source_class`** *(string)*: The class to which the this embedding profile applies.

  - **`description`** *(string)*: Description of the transformed class with embeddings.

  - **`embedded_references`** *(object)*: The references embedded into the target class.The keys are the names of slots in the target class that are used for  the references to other classes. The values are either the names of the referenced classes or other embedding profiles if a custom embedding will be applied to the referenced classes, too. Can contain additional properties.

    - **Additional Properties**

- **`CustomEmbeddingConfig`** *(object)*: Config to describe profiles for custom embeddings of classes from a metadata
model. Cannot contain additional properties.

  - **`embedding_profiles`** *(array)*: A list of custom embedding profiles for classes from a metadata model.

    - **Items**: Refer to *#/definitions/EmbeddingProfile*.

- **`ReferenceDetails`** *(object)*: A base model for describing an inferred reference that is based on existing
references.

  - **`path`** *(string)*: The path to reconstruct the new reference based on existing references.

  - **`multivalued`** *(boolean)*: Whether the new reference will be multivalued.

- **`ReferenceInferenceConfig`** *(object)*: Config containing inferred references for all classes of a metadata model in a
dictionary-based representation and the option to translate that reference map into
a list of InferredReferences. Cannot contain additional properties.

  - **`inferred_ref_map`** *(object)*: A nested dictionary describing inferred references based on existing references. On the first level keys refer to classes to which inferred references should be added. On the second level, keys refer to the names of the new slots of classes that hold the inferred references. The values refer to the actual references details. Can contain additional properties.

    - **Additional Properties** *(object)*: Can contain additional properties.

      - **Additional Properties**: Refer to *#/definitions/ReferenceDetails*.

- **`SlotMergeInstruction`** *(object)*: A model to describe slot merging instructions.

  - **`class_name`** *(string)*: The class to which the slots belong.

  - **`source_slots`** *(array)*: The slots that should be merged into the target slot.

    - **Items** *(string)*

  - **`target_slot`** *(string)*: The slot into which the source slots should be merged.

  - **`target_description`** *(string)*: A description of the target slot.

- **`SlotMergingConfig`** *(object)*: Config containing slots to be deleted from models and associated metadata. Cannot contain additional properties.

  - **`merge_instructions`** *(array)*: A list of slot merging instructions. Each instruction specifies a class and a target slot into which the source slots should be merged. You may specify merge instructions for the same class. However, the target slot of one merge instruction cannot be used as a source slot in another merge instruction. The source slots will not be deleted.

    - **Items**: Refer to *#/definitions/SlotMergeInstruction*.

- **`SlotDeletionConfig`** *(object)*: Config containing slots to be deleted from models and associated metadata. Cannot contain additional properties.

  - **`slots_to_delete`** *(object)*: A nested dictionary specifying slots that should be deleted per class. The keys refer to classes, the values to the slots that should be deleted from the respective class. Can contain additional properties.

    - **Additional Properties** *(array)*

      - **Items** *(string)*

- **`SpecificWorkflowConfig`** *(object)*: A base class for workflow configs.

  - **`add_accessions`**: Refer to *#/definitions/AccessionAdditionConfig*.

  - **`embed_restricted`**: Refer to *#/definitions/CustomEmbeddingConfig*.

  - **`infer_multiway_references`**: Refer to *#/definitions/ReferenceInferenceConfig*.

  - **`merge_dataset_file_lists`**: Refer to *#/definitions/SlotMergingConfig*.

  - **`remove_restricted_metadata`**: Refer to *#/definitions/SlotDeletionConfig*.

  - **`embed_public`**: Refer to *#/definitions/CustomEmbeddingConfig*.
