import { documentsClient } from '@dynatrace-sdk/client-document';

/**
 * Get a specific notebook by ID
 * @param notebookId The unique identifier of the notebook
 * @returns Notebook document with full content
 */
export const getNotebook = async (notebookId: string) => {
  const response = await documentsClient.getDocument({
    id: notebookId,
  });

  return response;
};
