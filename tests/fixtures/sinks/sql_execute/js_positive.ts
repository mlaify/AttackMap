import { type Request, type Response } from 'express'

export function searchProducts () {
  return (req: Request, res: Response) => { // taint: route
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${criteria}%' ORDER BY name`) // taint: sink
      .then(([products]: any) => res.json(products))
  }
}
