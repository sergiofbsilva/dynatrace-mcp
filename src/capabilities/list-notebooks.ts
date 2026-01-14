import { documentsClient } from '@dynatrace-sdk/client-document';

/**
 * List all notebooks from the Dynatrace environment
 * @param filter Optional filter to apply (e.g., "name='MyNotebook'")
 * @returns List of notebooks with their metadata
 */
export const listNotebooks = async (filter?: string) => {
  // Build filter string - always filter for type='notebook'
  let filterQuery = "type='notebook'";
  if (filter) {
    filterQuery += ` and ${filter}`;
  }

  const response = await documentsClient.listDocuments({
    filter: filterQuery,
  });

  return response;
};
