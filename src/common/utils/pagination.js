'use strict';

function paginate(req) {
  const page   = Math.max(1, parseInt(req.query.page)  || 1);
  const limit  = Math.min(100, parseInt(req.query.limit) || 20);
  const offset = (page - 1) * limit;
  return { page, limit, offset };
}

function paginatedResponse(rows, total, page, limit) {
  return {
    data: rows,
    meta: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
      hasNext:    page * limit < total,
      hasPrev:    page > 1,
    },
  };
}

function sortClause(req, allowedFields, defaultField = 'created_at', defaultDir = 'DESC') {
  const field = allowedFields.includes(req.query.sort) ? req.query.sort : defaultField;
  const dir   = req.query.dir?.toUpperCase() === 'ASC' ? 'ASC' : defaultDir;
  return `ORDER BY ${field} ${dir}`;
}

module.exports = { paginate, paginatedResponse, sortClause };
