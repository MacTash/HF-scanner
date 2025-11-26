"""
HuggingFace API utility functions.
Handles interaction with HuggingFace Hub API.
"""

import time
from typing import Dict, List, Optional, Any
from huggingface_hub import HfApi, ModelInfo, hf_hub_url, list_repo_files
from huggingface_hub.utils import RepositoryNotFoundError, HfHubHTTPError
from .logger import get_logger

logger = get_logger(__name__)


class HFAPIClient:
    """Client for interacting with HuggingFace Hub API."""
    
    def __init__(self, token: Optional[str] = None, timeout: int = 30):
        """
        Initialize HF API client.
        
        Args:
            token: HuggingFace API token (optional)
            timeout: Request timeout in seconds
        """
        self.api = HfApi(token=token)
        self.timeout = timeout
        self._last_request_time = 0
        self._min_request_interval = 0.1  # Rate limiting
        
    def _rate_limit(self):
        """Apply rate limiting between requests."""
        current_time = time.time()
        time_since_last = current_time - self._last_request_time
        if time_since_last < self._min_request_interval:
            time.sleep(self._min_request_interval - time_since_last)
        self._last_request_time = time.time()
    
    def get_model_info(self, model_id: str) -> Optional[ModelInfo]:
        """
        Get model information from HuggingFace Hub.
        
        Args:
            model_id: Model identifier (e.g., "gpt2", "bert-base-uncased")
            
        Returns:
            ModelInfo object or None if not found
        """
        self._rate_limit()
        
        try:
            logger.info(f"Fetching model info for: {model_id}")
            model_info = self.api.model_info(model_id, timeout=self.timeout)
            return model_info
        except RepositoryNotFoundError:
            logger.error(f"Model not found: {model_id}")
            return None
        except HfHubHTTPError as e:
            logger.error(f"HTTP error fetching model {model_id}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error fetching model info for {model_id}: {e}")
            return None
    
    def list_model_files(self, model_id: str) -> List[str]:
        """
        List all files in a model repository.
        
        Args:
            model_id: Model identifier
            
        Returns:
            List of file paths in the repository
        """
        self._rate_limit()
        
        try:
            logger.debug(f"Listing files for model: {model_id}")
            files = list_repo_files(model_id, repo_type="model")
            return files
        except RepositoryNotFoundError:
            logger.error(f"Model not found: {model_id}")
            return []
        except Exception as e:
            logger.error(f"Error listing files for {model_id}: {e}")
            return []
    
    def get_file_url(self, model_id: str, filename: str) -> str:
        """
        Get the URL for a specific file in a model repository.
        
        Args:
            model_id: Model identifier
            filename: File path in repository
            
        Returns:
            URL to the file
        """
        return hf_hub_url(model_id, filename=filename, repo_type="model")
    
    def extract_model_metadata(self, model_info: ModelInfo) -> Dict[str, Any]:
        """
        Extract useful metadata from ModelInfo object.
        
        Args:
            model_info: HuggingFace ModelInfo object
            
        Returns:
            Dictionary of metadata
        """
        metadata = {
            "model_id": model_info.modelId,
            "author": model_info.author if hasattr(model_info, "author") else None,
            "sha": model_info.sha,
            "created_at": str(model_info.created_at) if hasattr(model_info, "created_at") else None,
            "last_modified": str(model_info.lastModified) if hasattr(model_info, "lastModified") else None,
            "private": model_info.private,
            "downloads": model_info.downloads if hasattr(model_info, "downloads") else 0,
            "likes": model_info.likes if hasattr(model_info, "likes") else 0,
            "tags": model_info.tags if model_info.tags else [],
            "pipeline_tag": model_info.pipeline_tag if hasattr(model_info, "pipeline_tag") else None,
            "library_name": model_info.library_name if hasattr(model_info, "library_name") else None,
            "license": getattr(model_info.card_data, "license", None) if model_info.card_data else None,
        }
        
        return metadata
    
    def get_model_card(self, model_id: str) -> Optional[str]:
        """
        Get the model card (README) content.
        
        Args:
            model_id: Model identifier
            
        Returns:
            Model card content or None
        """
        self._rate_limit()
        
        try:
            model_info = self.get_model_info(model_id)
            if model_info and hasattr(model_info, "card_data"):
                return model_info.card_data
            return None
        except Exception as e:
            logger.error(f"Error fetching model card for {model_id}: {e}")
            return None

    def get_dataset_info(self, dataset_id: str) -> Optional[Any]:
        """
        Get dataset information from HuggingFace Hub.
        
        Args:
            dataset_id: Dataset identifier
            
        Returns:
            DatasetInfo object or None if not found
        """
        self._rate_limit()
        
        try:
            logger.info(f"Fetching dataset info for: {dataset_id}")
            dataset_info = self.api.dataset_info(dataset_id, timeout=self.timeout)
            return dataset_info
        except Exception as e:
            logger.warning(f"Error fetching dataset info for {dataset_id}: {e}")
            return None

    def list_dataset_files(self, dataset_id: str) -> List[str]:
        """
        List all files in a dataset repository.
        
        Args:
            dataset_id: Dataset identifier
            
        Returns:
            List of file paths in the repository
        """
        self._rate_limit()
        
        try:
            logger.debug(f"Listing files for dataset: {dataset_id}")
            files = list_repo_files(dataset_id, repo_type="dataset")
            return files
        except Exception as e:
            logger.warning(f"Error listing files for dataset {dataset_id}: {e}")
            return []
