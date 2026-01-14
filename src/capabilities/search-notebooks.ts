import { documentsClient } from '@dynatrace-sdk/client-document';

export interface SearchNotebooksOptions {
  searchText?: string;
  owner?: string;
  createdAfter?: string;
  createdBefore?: string;
  modifiedAfter?: string;
  modifiedBefore?: string;
  sortBy?: string;
  pageSize?: number;
}

/**
 * Search for notebooks with various filter criteria
 * @param options Search options
 * @returns List of notebooks matching the search criteria
 */
export const searchNotebooks = async (options: SearchNotebooksOptions) => {
  const filters: string[] = ["type='notebook'"];

  // Text search - searches in notebook names (case insensitive)
  if (options.searchText) {
    filters.push(`name contains '${options.searchText}'`);
  }

  // Owner filter
  if (options.owner) {
    filters.push(`owner == '${options.owner}'`);
  }

  // Date range filters
  if (options.createdAfter) {
    filters.push(`modificationInfo.createdTime >= '${options.createdAfter}'`);
  }
  if (options.createdBefore) {
    filters.push(`modificationInfo.createdTime <= '${options.createdBefore}'`);
  }
  if (options.modifiedAfter) {
    filters.push(`modificationInfo.lastModifiedTime >= '${options.modifiedAfter}'`);
  }
  if (options.modifiedBefore) {
    filters.push(`modificationInfo.lastModifiedTime <= '${options.modifiedBefore}'`);
  }

  const filterQuery = filters.join(' and ');

  const response = await documentsClient.listDocuments({
    filter: filterQuery,
    sort: options.sortBy || '-modificationInfo.lastModifiedTime', // Default: newest first
    pageSize: options.pageSize || 50,
    addFields: 'description', // Include description in results
  });

  return response;
};
