import { type Request, type Response } from 'express'

export function searchProducts () {
  return (req: Request, res: Response) => { // taint: route
    const criteria: string = String(req.query.q ?? '')
    models.sequelize.query('SELECT * FROM Products WHERE name LIKE :q ORDER BY name', { replacements: { q: `%${criteria}%` } }) // taint: sink
      .then(([products]: any) => res.json(products))
  }
}
